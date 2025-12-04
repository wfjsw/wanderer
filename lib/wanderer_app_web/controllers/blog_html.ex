defmodule WandererAppWeb.BlogHTML do
  use WandererAppWeb, :html

  embed_templates "blog_html/*"

  @doc """
  Check if WinterCo SEAT authentication is enabled.
  Delegates to WandererApp.Env.winterco_auth_enabled?/0
  """
  def winterco_auth_enabled? do
    WandererApp.Env.winterco_auth_enabled?()
  end
end
