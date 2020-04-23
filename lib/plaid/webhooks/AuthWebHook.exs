defmodule Plaid.Webhooks.WebHook do
  @moduledoc """
  """
  defmodule PlaidError do
    @type t :: %__MODULE__{
            display_message: String.t(),
            error_code: String.t(),
            error_message: String.t(),
            error_type: String.t()
          }

    @derive Jason.Encoder
    defstruct [
      :display_message,
      :error_code,
      :error_message,
      :error_type
    ]
  end

  @type t :: %__MODULE__{
          webhook_type: String.t(),
          webhook_code: String.t(),
          item_id: String.t(),
          account_id: String.t(),
          error: PlaidError.t()
        }

  @derive Jason.Encoder
  defstruct [
    :webhook_type,
    :webhook_code,
    :item_id,
    :account_id,
    :error
  ]
end
