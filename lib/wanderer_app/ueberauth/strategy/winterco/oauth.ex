defmodule WandererApp.Ueberauth.Strategy.WinterCo.OAuth do
  @moduledoc """
  OAuth2 for WinterCo SEAT (OpenID Connect compliant).

  Add `client_id` and `client_secret` to your configuration:

      config :ueberauth, WandererApp.Ueberauth.Strategy.WinterCo.OAuth,
        client_id: System.get_env("WINTERCO_CLIENT_ID"),
        client_secret: System.get_env("WINTERCO_CLIENT_SECRET")

  This module:
  - Fetches OIDC configuration from .well-known/openid-configuration
  - Verifies JWT signatures on id_token
  - Parses user info from id_token claims (sub, nam, acct)
  - Uses passthrough endpoint for EVE token generation
  """
  use OAuth2.Strategy

  require Logger

  @defaults [
    strategy: __MODULE__,
    site: "https://seat.winterco.org"
  ]

  # Cache OIDC configuration for 1 hour
  @oidc_config_cache_key "winterco_oidc_config"
  @oidc_config_ttl :timer.hours(1)

  # Cache JWKS for 1 hour
  @jwks_cache_key "winterco_jwks"
  @jwks_ttl :timer.hours(1)

  @doc """
  Fetch OpenID Connect configuration from .well-known endpoint.
  """
  def get_oidc_config do
    case WandererApp.Cache.get(@oidc_config_cache_key) do
      nil ->
        fetch_and_cache_oidc_config()

      config ->
        {:ok, config}
    end
  end

  defp fetch_and_cache_oidc_config do
    site = get_site()
    url = "#{site}/.well-known/openid-configuration"

    case Req.get(url) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        WandererApp.Cache.put(@oidc_config_cache_key, body, ttl: @oidc_config_ttl)
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("Failed to fetch OIDC config: status #{status}, body: #{inspect(body)}")
        {:error, {:oidc_config_failed, status}}

      {:error, error} ->
        Logger.warning("Failed to fetch OIDC config: #{inspect(error)}")
        {:error, error}
    end
  end

  @doc """
  Fetch JWKS (JSON Web Key Set) for signature verification.
  """
  def get_jwks do
    case WandererApp.Cache.get(@jwks_cache_key) do
      nil ->
        fetch_and_cache_jwks()

      jwks ->
        {:ok, jwks}
    end
  end

  defp fetch_and_cache_jwks do
    case get_oidc_config() do
      {:ok, config} ->
        jwks_uri = Map.get(config, "jwks_uri")

        if jwks_uri do
          case Req.get(jwks_uri) do
            {:ok, %{status: 200, body: body}} when is_map(body) ->
              WandererApp.Cache.put(@jwks_cache_key, body, ttl: @jwks_ttl)
              {:ok, body}

            {:ok, %{status: status}} ->
              {:error, {:jwks_fetch_failed, status}}

            {:error, error} ->
              {:error, error}
          end
        else
          {:error, :no_jwks_uri}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Construct a client for requests to WinterCo SEAT.
  Fetches authorize_url and token_url from OIDC configuration.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, __MODULE__, [])
    json_library = Ueberauth.json_library()

    # Get OIDC endpoints dynamically
    {authorize_url, token_url} = get_oidc_endpoints()

    @defaults
    |> Keyword.merge(config)
    |> Keyword.merge(opts)
    |> Keyword.put(:authorize_url, authorize_url)
    |> Keyword.put(:token_url, token_url)
    |> resolve_values()
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  defp get_oidc_endpoints do
    case get_oidc_config() do
      {:ok, config} ->
        authorize_url = Map.get(config, "authorization_endpoint", "/oauth/authorize")
        token_url = Map.get(config, "token_endpoint", "/oauth/token")
        {authorize_url, token_url}

      {:error, _} ->
        # Fallback to defaults
        {"/oauth/authorize", "/oauth/token"}
    end
  end

  defp get_site do
    config = Application.get_env(:ueberauth, __MODULE__, [])
    Keyword.get(config, :site, @defaults[:site])
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> Keyword.put(:redirect_uri, "#{WandererApp.Env.base_url()}/auth/winterco/callback")
    |> client()
    |> OAuth2.Client.authorize_url!(params)
  end

  @doc """
  Get access token from WinterCo SEAT.
  """
  def get_access_token(params \\ [], opts \\ []) do
    case opts
         |> client()
         |> OAuth2.Client.get_token(params ++ [grant_type: "authorization_code"], []) do
      {:ok, %OAuth2.Client{token: token}} ->
        case Map.get(token, :access_token) do
          nil ->
            %{"error" => error, "error_description" => description} = token.other_params
            {:error, {error, description}}

          _ ->
            {:ok, token}
        end

      {:error, %OAuth2.Response{body: %{"error" => error}} = response} ->
        description = Map.get(response.body, "error_description", "")
        {:error, {error, description}}

      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, {"error", to_string(reason)}}
    end
  end

  @doc """
  Decode and verify the id_token JWT from the token response.
  Returns the claims from the JWT payload including sub, nam, and acct.
  """
  def decode_and_verify_id_token(token) do
    id_token = Map.get(token.other_params, "id_token")

    if is_nil(id_token) do
      {:error, :no_id_token}
    else
      case get_jwks() do
        {:ok, jwks} ->
          verify_jwt(id_token, jwks)

        {:error, _} = error ->
          error
      end
    end
  end

  defp verify_jwt(jwt_string, jwks) do
    # Parse the JWKS into JOSE format
    keys = Map.get(jwks, "keys", [])

    # Try to verify with each key until one succeeds
    result =
      Enum.find_value(keys, {:error, :invalid_signature}, fn key_map ->
        try do
          jwk = JOSE.JWK.from_map(key_map)

          case JOSE.JWT.verify_strict(jwk, ["RS256", "ES256"], jwt_string) do
            {true, %JOSE.JWT{fields: claims}, _jws} ->
              {:ok, claims}

            {false, _, _} ->
              nil
          end
        rescue
          _ -> nil
        end
      end)

    result
  end

  @doc """
  Extract EVE character accounts from the id_token claims.
  Filters out characters with valid=false.
  Returns a list of %{id: character_id, name: character_name}.
  """
  def extract_eve_accounts(claims) do
    acct = Map.get(claims, "acct", [])

    acct
    |> Enum.filter(fn account ->
      # Filter out accounts with valid=false
      Map.get(account, "valid", true) == true
    end)
    |> Enum.map(fn account ->
      %{
        id: Map.get(account, "id"),
        name: Map.get(account, "name")
      }
    end)
    |> Enum.filter(fn account ->
      # Ensure we have an id
      not is_nil(account.id)
    end)
  end

  @doc """
  Refresh the WinterCo access token using the refresh token.
  This should be called before using the passthrough endpoint if the access token is expired.
  """
  def refresh_winterco_token(winterco_refresh_token, opts \\ []) do
    if is_nil(winterco_refresh_token) do
      {:error, :no_refresh_token}
    else
      client =
        opts
        |> client()
        |> OAuth2.Client.put_param(:grant_type, "refresh_token")
        |> OAuth2.Client.put_param(:refresh_token, winterco_refresh_token)

      case OAuth2.Client.get_token(client, [], []) do
        {:ok, %OAuth2.Client{token: new_token}} ->
          case Map.get(new_token, :access_token) do
            nil ->
              {:error, :token_refresh_failed}

            _ ->
              {:ok, new_token}
          end

        {:error, %OAuth2.Response{body: %{"error" => error}} = response} ->
          description = Map.get(response.body, "error_description", "")
          Logger.warning("WinterCo token refresh failed: #{error} - #{description}")
          {:error, {error, description}}

        {:error, %OAuth2.Error{reason: reason}} ->
          Logger.warning("WinterCo token refresh error: #{inspect(reason)}")
          {:error, {"error", to_string(reason)}}
      end
    end
  end

  @doc """
  Get EVE Online token via WinterCo passthrough endpoint.
  This endpoint generates an EVE Online token for a character, similar to a refresh request on login.eveonline.com.
  """
  def get_eve_token_passthrough(eve_character_id, winterco_access_token, opts \\ []) do
    # Build a token struct for the OAuth2 client
    token = %OAuth2.AccessToken{
      access_token: winterco_access_token,
      token_type: "Bearer"
    }

    client = opts |> Keyword.put(:token, token) |> client()
    url = "/oauth/passthrough/#{eve_character_id}"

    case OAuth2.Client.get(client, url) do
      {:ok, %OAuth2.Response{status_code: 200, body: body}} when is_map(body) ->
        parse_eve_token_response(body)

      {:ok, %OAuth2.Response{status_code: status_code, body: body}} ->
        Logger.warning(
          "WinterCo passthrough failed for character #{eve_character_id} with status #{status_code}: #{inspect(body)}"
        )

        {:error, {:passthrough_failed, status_code}}

      {:error, error} ->
        Logger.warning(
          "WinterCo passthrough error for character #{eve_character_id}: #{inspect(error)}"
        )

        {:error, error}
    end
  end

  @doc """
  Refresh EVE token via WinterCo passthrough endpoint.
  This is used instead of the standard EVE SSO token refresh.
  
  The flow is:
  1. Get the stored WinterCo token from User (with refresh_token)
  2. Refresh the WinterCo access token using its refresh_token if expired
  3. Use the fresh WinterCo access token to call passthrough for EVE token
  """
  def refresh_eve_token(eve_character_id, opts \\ []) do
    # Get the stored WinterCo token from User database
    case get_winterco_token_for_refresh(opts) do
      {:ok, {access_token, refresh_token, expires_at}} ->
        # First, ensure the WinterCo token is fresh by refreshing it if needed
        case ensure_fresh_winterco_token(access_token, refresh_token, expires_at, opts) do
          {:ok, fresh_access_token} ->
            get_eve_token_passthrough(eve_character_id, fresh_access_token, opts)

          {:error, _} = error ->
            error
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Ensure the WinterCo token is fresh. Refreshes it using refresh_token if needed.
  Also updates the User database with the new token.
  """
  def ensure_fresh_winterco_token(access_token, refresh_token, expires_at, opts \\ []) do
    # Check if token is expired (with a 5-minute buffer)
    current_time = DateTime.utc_now() |> DateTime.to_unix()

    is_expired =
      case expires_at do
        nil -> true
        exp when is_integer(exp) -> exp < current_time + 300
        _ -> true
      end

    if is_expired do
      case refresh_winterco_token(refresh_token, opts) do
        {:ok, new_token} ->
          # Update the User with new token
          update_user_winterco_token(new_token, opts)
          {:ok, new_token.access_token}

        {:error, _} = error ->
          error
      end
    else
      {:ok, access_token}
    end
  end

  defp update_user_winterco_token(new_token, opts) do
    user_id = Keyword.get(opts, :user_id)
    character_id = Keyword.get(opts, :character_id)

    actual_user_id =
      cond do
        not is_nil(user_id) ->
          user_id

        not is_nil(character_id) ->
          case WandererApp.Character.get_character(character_id) do
            {:ok, %{user_id: uid}} when not is_nil(uid) -> uid
            _ -> nil
          end

        true ->
          nil
      end

    if actual_user_id do
      case WandererApp.Api.User.by_id(actual_user_id) do
        {:ok, user} ->
          WandererApp.Api.User.update_winterco_token(user, %{
            winterco_access_token: new_token.access_token,
            winterco_refresh_token: new_token.refresh_token,
            winterco_expires_at: new_token.expires_at
          })

        _ ->
          :ok
      end
    end
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  # Private functions

  defp resolve_values(list) do
    for {key, value} <- list do
      {key, resolve_value(value)}
    end
  end

  defp resolve_value({m, f, a}) when is_atom(m) and is_atom(f), do: apply(m, f, a)
  defp resolve_value(v), do: v

  defp parse_eve_token_response(%{
         "access_token" => access_token,
         "token_type" => token_type,
         "expires_in" => expires_in
       } = body) do
    expires_at = DateTime.utc_now() |> DateTime.add(expires_in, :second) |> DateTime.to_unix()

    token = %OAuth2.AccessToken{
      access_token: access_token,
      token_type: token_type,
      expires_at: expires_at,
      refresh_token: Map.get(body, "refresh_token"),
      other_params: Map.drop(body, ["access_token", "token_type", "expires_in", "refresh_token"])
    }

    {:ok, token}
  end

  defp parse_eve_token_response(body) do
    Logger.warning("Unexpected EVE token response format: #{inspect(body)}")
    {:error, :invalid_token_format}
  end

  defp get_winterco_token_for_refresh(opts) do
    # Get the WinterCo token from User database
    user_id = Keyword.get(opts, :user_id)
    character_id = Keyword.get(opts, :character_id)

    actual_user_id =
      cond do
        not is_nil(user_id) ->
          user_id

        not is_nil(character_id) ->
          case WandererApp.Character.get_character(character_id) do
            {:ok, %{user_id: uid}} when not is_nil(uid) -> uid
            _ -> nil
          end

        true ->
          nil
      end

    if actual_user_id do
      case WandererApp.Api.User.by_id(actual_user_id) do
        {:ok, user} ->
          access_token = Map.get(user, :winterco_access_token)
          refresh_token = Map.get(user, :winterco_refresh_token)
          expires_at = Map.get(user, :winterco_expires_at)

          if refresh_token do
            {:ok, {access_token, refresh_token, expires_at}}
          else
            {:error, :no_winterco_token}
          end

        _ ->
          {:error, :user_not_found}
      end
    else
      {:error, :no_user_id}
    end
  end
end
