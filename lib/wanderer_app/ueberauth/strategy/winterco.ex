defmodule WandererApp.Ueberauth.Strategy.WinterCo do
  @moduledoc """
  WinterCo SEAT Strategy for Überauth (OpenID Connect compliant).

  This strategy authenticates users via WinterCo SEAT and provides access
  to multiple EVE Online character tokens through the passthrough endpoint.
  """

  use Ueberauth.Strategy,
    uid_field: "sub",
    default_scope: "openid profile email eve-online"

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
            fetch_user(conn, token)

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
      name: Map.get(user, "name") || Map.get(user, "preferred_username"),
      nickname: Map.get(user, "preferred_username"),
      urls: %{
        profile: Map.get(user, "profile")
      }
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

  defp fetch_user(conn, token) do
    conn = put_private(conn, :winterco_token, token)

    case WandererApp.Ueberauth.Strategy.WinterCo.OAuth.get_user_info(token) do
      {:ok, user} ->
        conn
        |> put_private(:winterco_user, user)
        |> maybe_fetch_eve_characters(token, user)

      {:error, error} ->
        set_errors!(conn, [error("userinfo", inspect(error))])
    end
  end

  defp maybe_fetch_eve_characters(conn, token, user) do
    # If the user info contains EVE character IDs, fetch their tokens
    eve_character_ids = extract_eve_character_ids(user)

    if Enum.empty?(eve_character_ids) do
      conn
    else
      characters =
        eve_character_ids
        |> Enum.map(fn eve_id ->
          case WandererApp.Ueberauth.Strategy.WinterCo.OAuth.get_eve_token_passthrough(
                 eve_id,
                 token
               ) do
            {:ok, eve_token} ->
              %{eve_id: eve_id, token: eve_token}

            {:error, error} ->
              Logger.warning("Failed to get EVE token for character #{eve_id}: #{inspect(error)}")
              nil
          end
        end)
        |> Enum.reject(&is_nil/1)

      put_private(conn, :winterco_characters, characters)
    end
  end

  defp extract_eve_character_ids(user) do
    # Extract EVE character IDs from user info
    # The format depends on WinterCo SEAT's userinfo response structure
    # This may contain a list of character IDs or a structured list of characters
    cond do
      Map.has_key?(user, "eve_characters") ->
        user["eve_characters"]
        |> Enum.map(&extract_character_id/1)
        |> Enum.reject(&is_nil/1)

      Map.has_key?(user, "character_ids") ->
        user["character_ids"]
        |> Enum.map(&to_string/1)

      Map.has_key?(user, "eve_id") ->
        [to_string(user["eve_id"])]

      true ->
        []
    end
  end

  defp extract_character_id(character) when is_map(character) do
    Map.get(character, "eve_id") || Map.get(character, "character_id") || Map.get(character, "id")
    |> case do
      nil -> nil
      id -> to_string(id)
    end
  end

  defp extract_character_id(character_id) when is_integer(character_id),
    do: to_string(character_id)

  defp extract_character_id(character_id) when is_binary(character_id), do: character_id
  defp extract_character_id(_), do: nil

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
