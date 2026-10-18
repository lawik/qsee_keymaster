defmodule QseeKeymaster.Message do
  @moduledoc """
  Request and response bodies of the Keymaster key operations.

  These are the AOSP `android_keymaster_messages.cpp` serializations
  (Apache 2.0), the same code Qualcomm's client links in alongside the
  `AuthorizationSet` serializer in `QseeKeymaster.ParamSet`. The vendor
  wraps each body in a QSEE command buffer: the 32-bit command ID comes
  first (added by `QseeKeymaster.request/2`), the body follows.

  Every integer is little-endian. A `buffer` or key blob is a 32-bit
  length followed by that many bytes. A parameter set is the
  `AuthorizationSet` format. Several bodies depend on the negotiated
  message version; the Fairphone 3's TA 4.164 uses version 3, the default
  here.

  ## Request encoders

  Each returns the body for the matching command in `QseeKeymaster.Command`.

  ## Response decoders

  Each takes the body the application returned and gives `{:ok, map}` or
  `{:error, {:keymaster, code}}`. A response begins with a signed 32-bit
  Keymaster error; a non-zero error carries no further data.
  """

  alias QseeKeymaster.ParamSet

  @default_version 3

  @doc "Default negotiated message version for the Fairphone 3 TA."
  def default_version, do: @default_version

  ## --- primitives ---

  defp u32(n), do: <<n::little-32>>
  defp u64(n), do: <<n::little-64>>
  defp buffer(bin) when is_binary(bin), do: <<byte_size(bin)::little-32, bin::binary>>

  ## --- request encoders ---

  @doc "generate_key body: the key description parameter set."
  def generate_key(params), do: ParamSet.encode(params)

  @doc "get_key_characteristics body: key blob, then additional parameters."
  def get_key_characteristics(key_blob, add_params \\ []),
    do: buffer(key_blob) <> ParamSet.encode(add_params)

  @doc "import_key body: key description, key format, then the key material."
  def import_key(params, key_format, key_data) when is_integer(key_format),
    do: ParamSet.encode(params) <> u32(key_format) <> buffer(key_data)

  @doc "export_key body: additional parameters, key format, then the key blob."
  def export_key(add_params, key_format, key_blob) when is_integer(key_format),
    do: ParamSet.encode(add_params) <> u32(key_format) <> buffer(key_blob)

  @doc "begin body: purpose, key blob, then additional parameters."
  def begin(purpose, key_blob, add_params \\ []) when is_integer(purpose),
    do: u32(purpose) <> buffer(key_blob) <> ParamSet.encode(add_params)

  @doc "update body: operation handle, input, then additional parameters (version > 0)."
  def update(op_handle, input, add_params \\ [], version \\ @default_version) do
    base = u64(op_handle) <> buffer(input)
    if version > 0, do: base <> ParamSet.encode(add_params), else: base
  end

  @doc """
  finish body: operation handle, signature, additional parameters
  (version > 0) and input (version > 2).
  """
  def finish(
        op_handle,
        signature \\ <<>>,
        add_params \\ [],
        input \\ <<>>,
        version \\ @default_version
      ) do
    base = u64(op_handle) <> buffer(signature)
    base = if version > 0, do: base <> ParamSet.encode(add_params), else: base
    if version > 2, do: base <> buffer(input), else: base
  end

  @doc "abort body: the operation handle."
  def abort(op_handle), do: u64(op_handle)

  ## --- response decoders ---

  @doc "Peel the leading signed 32-bit Keymaster error off a response body."
  def error(<<code::little-signed-32, rest::binary>>), do: {code, rest}
  def error(_), do: {:error, :short_response}

  defp with_ok(body, fun) do
    case body do
      <<0::little-signed-32, rest::binary>> -> fun.(rest)
      <<code::little-signed-32, _::binary>> -> {:error, {:keymaster, code}}
      _ -> {:error, :short_response}
    end
  end

  @doc "generate_key / import_key response: key blob, enforced, unenforced."
  def decode_key_response(body) do
    with_ok(body, fn rest ->
      with <<len::little-32, key_blob::binary-size(len), r1::binary>> <- rest,
           {:ok, enforced, r2} <- ParamSet.decode(r1),
           {:ok, unenforced, _} <- ParamSet.decode(r2) do
        {:ok, %{key_blob: key_blob, enforced: enforced, unenforced: unenforced}}
      else
        other -> decode_fail(other)
      end
    end)
  end

  @doc "get_key_characteristics response: enforced, unenforced."
  def decode_characteristics(body) do
    with_ok(body, fn rest ->
      with {:ok, enforced, r1} <- ParamSet.decode(rest),
           {:ok, unenforced, _} <- ParamSet.decode(r1) do
        {:ok, %{enforced: enforced, unenforced: unenforced}}
      else
        other -> decode_fail(other)
      end
    end)
  end

  @doc "begin response: operation handle, then output parameters (version > 0)."
  def decode_begin(body, version \\ @default_version) do
    with_ok(body, fn rest ->
      with <<op_handle::little-64, r1::binary>> <- rest,
           {:ok, output_params} <- maybe_params(r1, version > 0) do
        {:ok, %{op_handle: op_handle, output_params: output_params}}
      else
        other -> decode_fail(other)
      end
    end)
  end

  @doc "update response: output, input_consumed (version > 0), output params (version > 1)."
  def decode_update(body, version \\ @default_version) do
    with_ok(body, fn rest ->
      with <<olen::little-32, output::binary-size(olen), r1::binary>> <- rest,
           {:ok, input_consumed, r2} <- maybe_u32(r1, version > 0),
           {:ok, output_params} <- maybe_params(r2, version > 1) do
        {:ok, %{output: output, input_consumed: input_consumed, output_params: output_params}}
      else
        other -> decode_fail(other)
      end
    end)
  end

  @doc "finish response: output, then output parameters (version > 1)."
  def decode_finish(body, version \\ @default_version) do
    with_ok(body, fn rest ->
      with <<olen::little-32, output::binary-size(olen), r1::binary>> <- rest,
           {:ok, output_params} <- maybe_params(r1, version > 1) do
        {:ok, %{output: output, output_params: output_params}}
      else
        other -> decode_fail(other)
      end
    end)
  end

  @doc "abort response: just the error word."
  def decode_abort(body), do: with_ok(body, fn _ -> {:ok, %{}} end)

  @doc "export_key response: the exported key material."
  def decode_export(body) do
    with_ok(body, fn rest ->
      case rest do
        <<len::little-32, key_data::binary-size(len), _::binary>> -> {:ok, %{key_data: key_data}}
        other -> decode_fail(other)
      end
    end)
  end

  defp maybe_params(_rest, false), do: {:ok, []}

  defp maybe_params(rest, true) do
    case ParamSet.decode(rest) do
      {:ok, params, _} -> {:ok, params}
      other -> other
    end
  end

  defp maybe_u32(rest, false), do: {:ok, nil, rest}
  defp maybe_u32(<<v::little-32, rest::binary>>, true), do: {:ok, v, rest}
  defp maybe_u32(_, true), do: {:error, :short_response}

  defp decode_fail({:error, _} = e), do: e
  defp decode_fail(bin) when is_binary(bin), do: {:error, :short_response}
  defp decode_fail(_), do: {:error, :malformed_response}
end
