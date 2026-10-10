defmodule QseeKeymaster.Transport do
  @moduledoc """
  How request bytes reach the trusted application.

  A transport is a function `(request, response_length) -> {:ok, response} | {:error, reason}`
  or a module implementing this behaviour. The default,
  `QseeKeymaster.Transport.Device`, writes to `/dev/qseecom_raw`, the shim
  the `tee-qseecom` nerves_system_fp3 kernel exposes.
  """

  @callback send(request :: binary(), rsp_len :: pos_integer(), opts :: keyword()) ::
              {:ok, binary()} | {:error, term()}

  @doc false
  def call(fun, req, rsp_len, _opts) when is_function(fun, 2), do: fun.(req, rsp_len)
  def call(mod, req, rsp_len, opts) when is_atom(mod), do: mod.send(req, rsp_len, opts)
end

defmodule QseeKeymaster.Transport.Device do
  @moduledoc """
  Transport over `/dev/qseecom_raw`.

  One write carries the application name and the request; the next read
  returns the kernel's status, the application's QSEE ID and the response
  buffer:

      write: <<name_len::little-32, rsp_len::little-32>> <> app_name <> request
      read:  <<status::little-signed-32, app_id::little-32, rsp::binary>>

  Options: `:device` (default `/dev/qseecom_raw`), `:app` (default
  `"keymaster64"`, the name the Keymaster application registers itself
  under; the partition it is loaded from is called `keymaster`).
  """

  @behaviour QseeKeymaster.Transport

  @default_device "/dev/qseecom_raw"
  @default_app "keymaster64"

  @impl true
  def send(request, rsp_len, opts \\ []) do
    device = Keyword.get(opts, :device, @default_device)
    app = Keyword.get(opts, :app, @default_app)
    packet = <<byte_size(app)::little-32, rsp_len::little-32>> <> app <> request

    with {:ok, fd} <- :file.open(device, [:raw, :binary, :read, :write]) do
      try do
        with :ok <- :file.write(fd, packet),
             {:ok, <<status::little-signed-32, _app_id::little-32, rsp::binary>>} <-
               :file.read(fd, 8 + rsp_len) do
          case status do
            0 -> {:ok, rsp}
            -2 -> {:error, :app_not_found}
            -5 -> {:error, {:tee_error, rsp}}
            -19 -> {:error, :scm_unavailable}
            n -> {:error, {:errno, n}}
          end
        else
          :eof -> {:error, :no_response}
          {:error, reason} -> {:error, reason}
        end
      after
        :file.close(fd)
      end
    end
  end

  @doc "Look up the application's QSEE ID without sending it anything."
  def lookup(opts \\ []) do
    device = Keyword.get(opts, :device, @default_device)
    app = Keyword.get(opts, :app, @default_app)
    packet = <<byte_size(app)::little-32, 0::little-32>> <> app

    with {:ok, fd} <- :file.open(device, [:raw, :binary, :read, :write]) do
      try do
        with :ok <- :file.write(fd, packet),
             {:ok, <<0::little-signed-32, app_id::little-32>>} <- :file.read(fd, 8) do
          {:ok, app_id}
        else
          {:ok, <<-2::little-signed-32, _::binary>>} -> {:error, :app_not_found}
          {:ok, <<n::little-signed-32, _::binary>>} -> {:error, {:errno, n}}
          other -> {:error, other}
        end
      after
        :file.close(fd)
      end
    end
  end
end
