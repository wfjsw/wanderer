defmodule WandererAppWeb.WinterCoAuthController do
  @moduledoc """
  Authentication controller for WinterCo SEAT OAuth.

  This controller handles the OAuth callback from WinterCo SEAT and
  creates/updates multiple EVE Online characters from the passthrough tokens.
  """

  use WandererAppWeb, :controller
  plug Ueberauth

  import Plug.Conn
  import Phoenix.Controller

  require Logger

  # Constants
  @winterco_cache_prefix "winterco_token_"
  @eve_token_verify_url "https://login.eveonline.com/oauth/verify"
  @winterco_character_owner_prefix "winterco_"

  @doc """
  Handles the initial OAuth request to WinterCo SEAT.
  Ueberauth handles this automatically through the strategy.
  """
  def request(conn, _params) do
    # Ueberauth handles the redirect in the strategy's handle_request!/1
    # If we reach here, something went wrong
    conn
    |> put_flash(:error, "WinterCo authentication is not properly configured.")
    |> redirect(to: "/welcome")
  end

  @doc """
  Handles the OAuth callback from WinterCo SEAT.

  This callback:
  1. Authenticates the user via WinterCo SEAT
  2. Retrieves EVE Online tokens for all linked characters via passthrough
  3. Creates/updates all characters in the system
  4. Creates the user if needed and links all characters
  """
  def callback(%{assigns: %{ueberauth_auth: auth, current_user: user} = _assigns} = conn, _params) do
    winterco_token = auth.extra.raw_info.token
    winterco_user = auth.extra.raw_info.user
    eve_characters = auth.extra.raw_info.eve_characters || []

    # Store the WinterCo token for future EVE token refreshes
    user_identifier = get_user_identifier(winterco_user, user)

    if user_identifier do
      WandererApp.Cache.put(
        @winterco_cache_prefix <> to_string(user_identifier),
        winterco_token,
        ttl: :timer.hours(24)
      )
    end

    active_tracking_pool = WandererApp.Character.TrackingConfigUtils.get_active_pool!()

    # Get or create user first
    user_id =
      case user do
        nil ->
          get_or_create_user_from_winterco(winterco_user)

        user ->
          user.id
      end

    # Process all EVE characters from the passthrough
    processed_characters =
      eve_characters
      |> Enum.map(fn %{eve_id: eve_id, token: eve_token} = _char ->
        process_eve_character(eve_id, eve_token, user_id, active_tracking_pool)
      end)
      |> Enum.reject(&is_nil/1)

    # Log the number of characters processed
    Logger.info(
      "WinterCo auth: Processed #{length(processed_characters)} EVE characters for user #{user_id}"
    )

    # Store the updated WinterCo token with the user_id
    WandererApp.Cache.put(
      @winterco_cache_prefix <> to_string(user_id),
      winterco_token,
      ttl: :timer.hours(24)
    )

    WandererApp.Character.TrackingConfigUtils.update_active_tracking_pool()

    conn
    |> put_session(:user_id, user_id)
    |> redirect(to: "/characters")
  end

  def callback(%{assigns: %{ueberauth_failure: failure}} = conn, _params) do
    Logger.warning("WinterCo auth callback failed: #{inspect(failure)}")

    conn
    |> put_flash(:error, "Authentication failed. Please try again.")
    |> redirect(to: "/welcome")
  end

  def callback(conn, _params) do
    Logger.warning("WinterCo auth callback: No auth data present")

    conn
    |> redirect(to: "/characters")
  end

  def signout(conn, _params) do
    # Clean up WinterCo token from cache
    user_id = get_session(conn, :user_id)

    if user_id do
      WandererApp.Cache.delete(@winterco_cache_prefix <> to_string(user_id))
    end

    conn
    |> configure_session(drop: true)
    |> redirect(to: ~p"/")
  end

  # Private functions

  defp get_user_identifier(winterco_user, nil) do
    # Use WinterCo user's sub or email as identifier
    Map.get(winterco_user, "sub") ||
      Map.get(winterco_user, "email") ||
      Map.get(winterco_user, "preferred_username")
  end

  defp get_user_identifier(_winterco_user, user), do: user.id

  defp get_or_create_user_from_winterco(winterco_user) do
    # Use the WinterCo user's sub as the hash for user identification
    user_hash = Map.get(winterco_user, "sub") || generate_uuid()
    user_name = Map.get(winterco_user, "name") || Map.get(winterco_user, "preferred_username")

    case WandererApp.Api.User.by_hash(user_hash) do
      {:ok, user} ->
        user.id

      _ ->
        :telemetry.execute([:wanderer_app, :user, :registered], %{count: 1})

        WandererApp.Api.User
        |> Ash.Changeset.for_create(:create, %{
          name: user_name || "User_#{user_hash}",
          hash: user_hash
        })
        |> Ash.create!()
        |> Map.get(:id)
    end
  end

  defp generate_uuid do
    # Use Ecto's ULID generation or fallback to simple random generation
    Ecto.UUID.generate()
  end

  defp process_eve_character(eve_id, eve_token, user_id, tracking_pool) do
    # First, get character info from ESI
    case get_character_info_from_token(eve_id, eve_token) do
      {:ok, character_info} ->
        character_data = %{
          eve_id: to_string(eve_id),
          name: character_info["CharacterName"] || character_info["name"],
          access_token: eve_token.access_token,
          refresh_token: eve_token.refresh_token,
          expires_at: eve_token.expires_at,
          scopes: Map.get(character_info, "Scopes", ""),
          tracking_pool: tracking_pool
        }

        character_owner_hash =
          Map.get(character_info, "CharacterOwnerHash") ||
            @winterco_character_owner_prefix <> to_string(eve_id)

        create_or_update_character(character_data, character_owner_hash, user_id)

      {:error, error} ->
        Logger.warning("Failed to get character info for EVE ID #{eve_id}: #{inspect(error)}")
        nil
    end
  end

  defp get_character_info_from_token(eve_id, eve_token) do
    # Verify the token and get character info
    case Req.get(@eve_token_verify_url, auth: {:bearer, eve_token.access_token}) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("Token verification failed with status #{status}: #{inspect(body)}")
        # Fallback: just use the eve_id we have
        {:ok, %{"CharacterID" => eve_id, "CharacterName" => "Character_#{eve_id}"}}

      {:error, error} ->
        Logger.warning("Token verification request failed: #{inspect(error)}")
        {:ok, %{"CharacterID" => eve_id, "CharacterName" => "Character_#{eve_id}"}}
    end
  end

  defp create_or_update_character(character_data, _character_owner_hash, user_id) do
    case WandererApp.Api.Character.by_eve_id(character_data.eve_id) do
      {:ok, character} ->
        # Update existing character
        character_update = %{
          name: character_data.name,
          access_token: character_data.access_token,
          refresh_token: character_data.refresh_token,
          expires_at: character_data.expires_at,
          scopes: character_data.scopes,
          tracking_pool: character_data.tracking_pool
        }

        case WandererApp.Api.Character.update(character, character_update) do
          {:ok, updated_character} ->
            WandererApp.Character.update_character(updated_character.id, character_update)
            # Ensure character is linked to user
            maybe_update_character_user_id(updated_character, user_id)
            updated_character

          {:error, error} ->
            Logger.warning("Failed to update character #{character_data.eve_id}: #{inspect(error)}")
            nil
        end

      {:error, _error} ->
        # Create new character
        case WandererApp.Api.Character.create(character_data) do
          {:ok, character} ->
            :telemetry.execute([:wanderer_app, :user, :character, :registered], %{count: 1})
            # Link character to user
            maybe_update_character_user_id(character, user_id)
            character

          {:error, error} ->
            Logger.warning("Failed to create character #{character_data.eve_id}: #{inspect(error)}")
            nil
        end
    end
  end

  defp maybe_update_character_user_id(character, user_id) when not is_nil(user_id) do
    case WandererApp.Api.Character.by_id(character.id) do
      {:ok, loaded_character} ->
        WandererApp.Api.Character.assign_user!(loaded_character, %{user_id: user_id})

      {:error, _} ->
        :ok
    end
  end

  defp maybe_update_character_user_id(_character, _user_id), do: :ok
end
