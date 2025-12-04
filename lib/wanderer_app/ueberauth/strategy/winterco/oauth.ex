defmodule WandererApp.Ueberauth.Strategy.WinterCo.OAuth do
  @moduledoc """
  OAuth2 for WinterCo SEAT (OpenID Connect compliant).

  Add `client_id` and `client_secret` to your configuration:

      config :ueberauth, WandererApp.Ueberauth.Strategy.WinterCo.OAuth,
        client_id: System.get_env("WINTERCO_CLIENT_ID"),
        client_secret: System.get_env("WINTERCO_CLIENT_SECRET")

  """
  use OAuth2.Strategy

  require Logger

  @defaults [
    strategy: __MODULE__,
    site: "https://seat.winterco.org",
    authorize_url: "/oauth/authorize",
    token_url: "/oauth/token",
    userinfo_url: "/oauth/userinfo"
  ]

  @doc """
  Construct a client for requests to WinterCo SEAT.

  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, __MODULE__, [])

    json_library = Ueberauth.json_library()

    @defaults
    |> Keyword.merge(config)
    |> Keyword.merge(opts)
    |> resolve_values()
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", json_library)
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
  Get user info from WinterCo SEAT (OpenID Connect userinfo endpoint).
  """
  def get_user_info(token, opts \\ []) do
    client = opts |> Keyword.put(:token, token) |> client()

    case OAuth2.Client.get(client, userinfo_url()) do
      {:ok, %OAuth2.Response{status_code: 200, body: body}} ->
        {:ok, body}

      {:ok, %OAuth2.Response{status_code: status_code, body: body}} ->
        Logger.warning("WinterCo userinfo failed with status #{status_code}: #{inspect(body)}")
        {:error, {:userinfo_failed, status_code}}

      {:error, error} ->
        Logger.warning("WinterCo userinfo error: #{inspect(error)}")
        {:error, error}
    end
  end

  @doc """
  Get EVE Online token via WinterCo passthrough endpoint.
  This endpoint generates an EVE Online token for a character, similar to a refresh request on login.eveonline.com.
  """
  def get_eve_token_passthrough(eve_character_id, winterco_token, opts \\ []) do
    client = opts |> Keyword.put(:token, winterco_token) |> client()
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
  """
  def refresh_eve_token(eve_character_id, opts \\ []) do
    # Get the stored WinterCo token for this session/user
    case get_winterco_token_for_refresh(opts) do
      {:ok, winterco_token} ->
        get_eve_token_passthrough(eve_character_id, winterco_token, opts)

      {:error, _} = error ->
        error
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

  defp userinfo_url do
    config = Application.get_env(:ueberauth, __MODULE__, [])
    Keyword.get(config, :userinfo_url, @defaults[:userinfo_url])
  end

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
    # Try to get the WinterCo token from cache or session
    user_id = Keyword.get(opts, :user_id)
    character_id = Keyword.get(opts, :character_id)

    cond do
      not is_nil(user_id) ->
        case WandererApp.Cache.get("winterco_token_#{user_id}") do
          nil -> {:error, :no_winterco_token}
          token -> {:ok, token}
        end

      not is_nil(character_id) ->
        # Try to find the user_id from character
        case WandererApp.Character.get_character(character_id) do
          {:ok, %{user_id: user_id}} when not is_nil(user_id) ->
            case WandererApp.Cache.get("winterco_token_#{user_id}") do
              nil -> {:error, :no_winterco_token}
              token -> {:ok, token}
            end

          _ ->
            {:error, :no_winterco_token}
        end

      true ->
        {:error, :no_winterco_token}
    end
  end
end
