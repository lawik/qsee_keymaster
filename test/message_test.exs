defmodule QseeKeymaster.MessageTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster.{Message, ParamSet}

  describe "request encoders" do
    test "abort is the 64-bit operation handle" do
      assert Message.abort(0x1122334455667788) ==
               <<0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11>>
    end

    test "generate_key is the key description parameter set" do
      params = [{:algorithm, :aes}, {:key_size, 256}]
      assert Message.generate_key(params) == ParamSet.encode(params)
    end

    test "begin is purpose, key blob, then additional params" do
      body = Message.begin(0, "KEY", [])
      assert <<0::little-32, 3::little-32, "KEY", rest::binary>> = body
      assert {:ok, [], ""} = ParamSet.decode(rest)
    end

    test "update at version 3 carries the additional params" do
      body = Message.update(7, "data", [{:mac_length, 128}], 3)
      assert <<7::little-64, 4::little-32, "data", rest::binary>> = body
      assert {:ok, [{:mac_length, 128}], ""} = ParamSet.decode(rest)
    end

    test "update at version 0 omits the additional params" do
      body = Message.update(7, "data", [{:mac_length, 128}], 0)
      assert body == <<7::little-64, 4::little-32, "data">>
    end

    test "finish at version 3 carries signature, params and input" do
      body = Message.finish(9, "sig", [], "in", 3)
      assert <<9::little-64, 3::little-32, "sig", rest::binary>> = body
      assert {:ok, [], <<2::little-32, "in">>} = ParamSet.decode(rest)
    end

    test "finish at version 2 omits the trailing input" do
      body = Message.finish(9, "sig", [], "in", 2)
      assert <<9::little-64, 3::little-32, "sig", rest::binary>> = body
      assert {:ok, [], ""} = ParamSet.decode(rest)
    end

    test "import_key is description, format, then material" do
      body = Message.import_key([{:algorithm, :aes}], 3, "raw-bytes")
      params = ParamSet.encode([{:algorithm, :aes}])
      assert body == params <> <<3::little-32, 9::little-32, "raw-bytes">>
    end
  end

  describe "response decoders" do
    test "a non-zero error short-circuits" do
      assert {:error, {:keymaster, -38}} = Message.decode_begin(<<-38::little-signed-32>>)
    end

    test "begin round-trips handle and output params" do
      params = ParamSet.encode([{:nonce, "abc"}])
      body = <<0::little-signed-32, 0xDEAD::little-64>> <> params

      assert {:ok, %{op_handle: 0xDEAD, output_params: [{:nonce, "abc"}]}} =
               Message.decode_begin(body, 3)
    end

    test "key response round-trips blob and characteristics" do
      enforced = ParamSet.encode([{:algorithm, :aes}])
      unenforced = ParamSet.encode([{:key_size, 256}])

      body =
        <<0::little-signed-32, 4::little-32, "blob">> <> enforced <> unenforced

      assert {:ok,
              %{key_blob: "blob", enforced: [{:algorithm, :aes}], unenforced: [{:key_size, 256}]}} =
               Message.decode_key_response(body)
    end

    test "update round-trips output, consumed count and params" do
      params = ParamSet.encode([])

      body =
        <<0::little-signed-32, 3::little-32, "out", 5::little-32>> <> params

      assert {:ok, %{output: "out", input_consumed: 5, output_params: []}} =
               Message.decode_update(body, 3)
    end

    test "finish round-trips output and params" do
      params = ParamSet.encode([])
      body = <<0::little-signed-32, 4::little-32, "sign">> <> params
      assert {:ok, %{output: "sign", output_params: []}} = Message.decode_finish(body, 3)
    end

    test "abort decodes to an empty map on success" do
      assert {:ok, %{}} = Message.decode_abort(<<0::little-signed-32>>)
    end

    test "export decodes the key material" do
      body = <<0::little-signed-32, 5::little-32, "mykey">>
      assert {:ok, %{key_data: "mykey"}} = Message.decode_export(body)
    end
  end
end
