defmodule QseeKeymaster do
  @moduledoc """
  Client for the Keymaster trusted application in Qualcomm's QSEE.

  On the Fairphone 3 the bootloader loads Keymaster 4 and leaves it
  resident in TrustZone, where it is the phone's only hardware-bound key
  store. This library speaks to it through a transport (see
  `QseeKeymaster.Transport`) and provides the pieces every request needs:
  command IDs (`QseeKeymaster.Command`), tags (`QseeKeymaster.Tag`) and
  the parameter-set wire format (`QseeKeymaster.ParamSet`).

  The utility commands the bootloader itself uses are public and verified
  against the phone: `version/1` and `date_support/1`. The request layout
  of the key operations is not public; `request/3` and `send/4` are the
  building blocks for them.

  Options accepted by every call: `:transport` (module or 2-arity
  function, default `QseeKeymaster.Transport.Device`), `:transport_opts`.
  """

  alias QseeKeymaster.{Command, Transport}

  @default_rsp_len 4096

  @doc """
  Keymaster's version: HAL major/minor and trusted application major/minor.

  Request is the command ID alone; the response is a signed status followed
  by four 32-bit version words. The Fairphone 3 answers HAL 4.0, TA 4.164.
  """
  def version(opts \\ []) do
    with {:ok,
          <<status::little-signed-32, major::little-32, minor::little-32, ta_major::little-32,
            ta_minor::little-32, _::binary>>} <-
           send(:get_version, <<>>, 64, opts) do
      if status == 0 do
        {:ok, %{major: major, minor: minor, ta_major: ta_major, ta_minor: ta_minor}}
      else
        {:error, {:keymaster, status}}
      end
    end
  end

  @doc "Whether the trusted application supports date tags. Response is a signed status."
  def date_support(opts \\ []) do
    with {:ok, <<status::little-signed-32, _::binary>>} <- send(:get_date_support, <<>>, 64, opts) do
      case status do
        0 -> {:ok, true}
        n -> {:error, {:keymaster, n}}
      end
    end
  end

  @doc "Build a request: the 32-bit command ID followed by `payload`."
  def request(command, payload \\ <<>>), do: <<Command.id(command)::little-32>> <> payload

  @doc """
  Send a command with a payload and return the raw response buffer.

  `rsp_len` is how large a response buffer to offer the application.
  """
  def send(command, payload \\ <<>>, rsp_len \\ @default_rsp_len, opts \\ []) do
    transport = Keyword.get(opts, :transport, Transport.Device)
    topts = Keyword.get(opts, :transport_opts, [])
    Transport.call(transport, request(command, payload), rsp_len, topts)
  end

  @doc "Interpret a response's leading signed 32-bit status."
  def status(<<status::little-signed-32, rest::binary>>), do: {status, rest}

  ## --- key operations ---
  ##
  ## These encode an AOSP Keymaster message with `QseeKeymaster.Message`,
  ## send it under the matching command ID, and decode the response the
  ## trusted application returns. They are the crypto surface: generate or
  ## import a hardware-bound key, then run an operation over begin/update/
  ## finish. The response framing assumes the application returns the AOSP
  ## message body directly, its leading word the Keymaster error.
  ##
  ## On the Fairphone 3's current kernel these block: key operations call
  ## back into the OS through a QSEE listener, which the mainline qseecom
  ## SCM path does not service (see the module docs). They are complete and
  ## will work once the kernel gains listener handling.

  alias QseeKeymaster.{Message, Tag}

  @version Message.default_version()

  @doc "Generate a hardware-bound key from a parameter set. Returns the key blob and its characteristics."
  def generate_key(params, opts \\ []) do
    with {:ok, rsp} <- send(:generate_key, Message.generate_key(params), rsp_len(opts), opts) do
      Message.decode_key_response(rsp)
    end
  end

  @doc "Import external key material under a parameter set and key format."
  def import_key(params, key_format, key_data, opts \\ []) do
    body = Message.import_key(params, Tag.key_format(key_format), key_data)

    with {:ok, rsp} <- send(:import_key, body, rsp_len(opts), opts) do
      Message.decode_key_response(rsp)
    end
  end

  @doc "Export the public part of a key in the given format."
  def export_key(key_blob, key_format, params \\ [], opts \\ []) do
    body = Message.export_key(params, Tag.key_format(key_format), key_blob)

    with {:ok, rsp} <- send(:export_key, body, rsp_len(opts), opts) do
      Message.decode_export(rsp)
    end
  end

  @doc "Read a key's enforced and unenforced characteristics."
  def get_key_characteristics(key_blob, params \\ [], opts \\ []) do
    body = Message.get_key_characteristics(key_blob, params)

    with {:ok, rsp} <- send(:get_key_characteristics, body, rsp_len(opts), opts) do
      Message.decode_characteristics(rsp)
    end
  end

  @doc """
  Begin an operation for a purpose over a key. Returns an operation handle
  and any output parameters (an initialisation vector, for example).

  `purpose` is a `:purpose` enum (`:encrypt`, `:decrypt`, `:sign`,
  `:verify`, `:derive_key`, `:wrap`) or an integer.
  """
  def begin(purpose, key_blob, params \\ [], opts \\ []) do
    body = Message.begin(Tag.enum_value(:purpose, purpose), key_blob, params)

    with {:ok, rsp} <- send(:begin, body, rsp_len(opts), opts) do
      Message.decode_begin(rsp, @version)
    end
  end

  @doc "Feed input to an operation. Returns output, bytes consumed and output parameters."
  def update(op_handle, input, params \\ [], opts \\ []) do
    body = Message.update(op_handle, input, params, @version)

    with {:ok, rsp} <- send(:update, body, rsp_len(opts), opts) do
      Message.decode_update(rsp, @version)
    end
  end

  @doc "Finish an operation, optionally with trailing input and a signature to verify."
  def finish(op_handle, input \\ <<>>, signature \\ <<>>, params \\ [], opts \\ []) do
    body = Message.finish(op_handle, signature, params, input, @version)

    with {:ok, rsp} <- send(:finish, body, rsp_len(opts), opts) do
      Message.decode_finish(rsp, @version)
    end
  end

  @doc "Abort an operation, releasing its handle."
  def abort(op_handle, opts \\ []) do
    with {:ok, rsp} <- send(:abort, Message.abort(op_handle), rsp_len(opts), opts) do
      Message.decode_abort(rsp)
    end
  end

  defp rsp_len(opts), do: Keyword.get(opts, :rsp_len, @default_rsp_len)
end
