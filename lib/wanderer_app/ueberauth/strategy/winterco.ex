defmodule WandererApp.Ueberauth.Strategy.WinterCo do
  @moduledoc """
  WinterCo SEAT Strategy for Überauth (OpenID Connect compliant).

  This strategy authenticates users via WinterCo SEAT and provides access
  to multiple EVE Online character tokens through the passthrough endpoint.

  User info is extracted from the id_token JWT claims:
  - sub: User identifier
  - nam: User name
  - acct: List of EVE accounts with {id, name, valid}
  """

  use Ueberauth.Strategy,
    uid_field: "sub",
    default_scope: "openid email groups accounts passthrough esi-location.read_location.v1 esi-location.read_ship_type.v1 esi-location.read_online.v1 esi-ui.write_waypoint.v1 esi-search.search_structures.v1"

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  require Logger

  @doc """
  Handles initial request for WinterCo authentication.
  """
  def handle_request!(conn) do
    scopes = option(conn, :default_scope) || conn.params["scope"]
    invite_token = Map.get(conn.params, "invite", nil)

    {invite_token_valid, _invite_type} = check_invite_valid(invite_token)

    case invite_token_valid do
      true ->
        params =
          [scope: scopes]
          |> with_optional(:prompt, conn)
          |> with_state_param(conn)

        # Store state in cache for callback verification
        WandererApp.Cache.put(
          "winterco_auth_#{params[:state]}",
          [],
          ttl: :timer.minutes(30)
        )

        redirect!(
          conn,
          WandererApp.Ueberauth.Strategy.WinterCo.OAuth.authorize_url!(params)
        )

      false ->
        conn
        |> redirect!("/welcome")
    end
  end

  @doc """
  Handles the callback from WinterCo SEAT.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => state}} = conn) do
    case WandererApp.Cache.get("winterco_auth_#{state}") do
      nil ->
        # Cache expired or invalid state - redirect to welcome page
        conn
        |> redirect!("/welcome")

      _opts ->
        params = [code: code]

        case WandererApp.Ueberauth.Strategy.WinterCo.OAuth.get_access_token(params) do
          {:ok, token} ->
            fetch_user_from_id_token(conn, token)

          {:error, {error_code, error_description}} ->
            set_errors!(conn, [error(error_code, error_description)])
        end
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:winterco_user, nil)
    |> put_private(:winterco_token, nil)
    |> put_private(:winterco_characters, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string()

    conn.private.winterco_user[uid_field]
  end

  @doc """
  Includes the credentials from the WinterCo response.
  """
  def credentials(conn) do
    token = conn.private.winterco_token
    user = conn.private.winterco_user

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: Map.get(user, "scope", ""),
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.winterco_user

    %Info{
      email: Map.get(user, "email"),
      name: Map.get(user, "nam") || Map.get(user, "name"),
      nickname: Map.get(user, "sub"),
      urls: %{}
    }
  end

  @doc """
  Stores the raw information (including the token and EVE characters) obtained from the callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.winterco_token,
        user: conn.private.winterco_user,
        eve_characters: conn.private[:winterco_characters] || []
      }
    }
  end

  defp fetch_user_from_id_token(conn, token) do
    conn = put_private(conn, :winterco_token, token)

    # Decode and verify the id_token JWT instead of calling userinfo endpoint
    case WandererApp.Ueberauth.Strategy.WinterCo.OAuth.decode_and_verify_id_token(token) do
      {:ok, claims} ->
        # Extract user info from JWT claims
        user = %{
          "sub" => Map.get(claims, "sub"),
          "nam" => Map.get(claims, "nam"),
          "email" => Map.get(claims, "email"),
          "acct" => Map.get(claims, "acct", [])
        }

        conn
        |> put_private(:winterco_user, user)
        |> fetch_eve_characters_from_acct(token, claims)

      {:error, error} ->
        Logger.warning("Failed to decode id_token: #{inspect(error)}")
        set_errors!(conn, [error("id_token", inspect(error))])
    end
  end

  defp fetch_eve_characters_from_acct(conn, token, claims) do
    # Extract EVE accounts from the acct claim, filtering out invalid ones
    eve_accounts = WandererApp.Ueberauth.Strategy.WinterCo.OAuth.extract_eve_accounts(claims)

    if Enum.empty?(eve_accounts) do
      conn
    else
      # Fetch EVE tokens for each valid account via passthrough
      characters =
        eve_accounts
        |> Enum.map(fn %{id: eve_id, name: name} ->
          case WandererApp.Ueberauth.Strategy.WinterCo.OAuth.get_eve_token_passthrough(
                 eve_id,
                 token.access_token
               ) do
            {:ok, eve_token} ->
              %{eve_id: to_string(eve_id), name: name, token: eve_token}

            {:error, error} ->
              Logger.warning("Failed to get EVE token for character #{eve_id}: #{inspect(error)}")
              nil
          end
        end)
        |> Enum.reject(&is_nil/1)

      put_private(conn, :winterco_characters, characters)
    end
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp check_invite_valid(invite_token) do
    case invite_token do
      token when not is_nil(token) and token != "" ->
        check_token_valid(token)

      _ ->
        {not WandererApp.Env.invites(), :user}
    end
  end

  defp check_token_valid(token) do
    WandererApp.Cache.lookup!("invite_#{token}", false)
    |> case do
      true -> {true, :user}
      _ -> check_map_token_valid(token)
    end
  end

  def check_map_token_valid(token) do
    {:ok, invites} = WandererApp.Api.MapInvite.read()

    invites
    |> Enum.find(fn invite -> invite.token == token end)
    |> case do
      nil -> {false, nil}
      invite -> {true, invite.type}
    end
  end
end
