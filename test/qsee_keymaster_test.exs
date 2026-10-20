defmodule QseeKeymasterTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster.Command

  test "command ids match LK's km_main.h" do
    assert Command.id(:generate_key) == 0x108
    assert Command.id(:begin) == 0x10F
    assert Command.id(:finish) == 0x112
    assert Command.id(:get_version) == 0x200
    assert Command.id(:get_date_support) == 0x215
    assert Command.name(0x204) == :milestone_call
    assert Command.name(0x2FF) == 0x2FF
  end

  test "version parses the response the phone gives, through a fake transport" do
    fake = fn <<0x200::little-32>>, 64 ->
      {:ok,
       <<0::little-signed-32, 4::little-32, 0::little-32, 4::little-32, 164::little-32,
         0::size(352)>>}
    end

    assert {:ok, %{major: 4, minor: 0, ta_major: 4, ta_minor: 164}} =
             QseeKeymaster.version(transport: fake)
  end

  test "a non-zero keymaster status is an error" do
    fake = fn _req, _len -> {:ok, <<-38::little-signed-32, 0::size(480)>>} end
    assert {:error, {:keymaster, -38}} = QseeKeymaster.version(transport: fake)
    assert {:error, {:keymaster, -38}} = QseeKeymaster.date_support(transport: fake)
  end

  test "request prefixes the command id" do
    assert QseeKeymaster.request(:abort, <<7::little-64>>) == <<0x113::little-32, 7::little-64>>
  end
end

defmodule QseeKeymaster.KeyOpsTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster, as: KM
  alias QseeKeymaster.{Command, Message, ParamSet}

  # A fake transport that decodes the command ID and replies with a
  # canned AOSP response body, so the high-level API is exercised end to end.
  defp transport(replies) do
    fn <<cmd::little-32, body::binary>>, _rsp_len ->
      name = Command.name(cmd)
      send(self(), {:sent, name, body})
      {:ok, Map.fetch!(replies, name)}
    end
  end

  test "generate_key encodes params and decodes the key response" do
    enforced = ParamSet.encode([{:origin, :generated}])
    unenforced = ParamSet.encode([{:key_size, 256}])
    reply = <<0::little-signed-32, 5::little-32, "BLOB!">> <> enforced <> unenforced

    opts = [transport: transport(%{generate_key: reply})]
    params = [{:algorithm, :aes}, {:key_size, 256}]

    assert {:ok,
            %{
              key_blob: "BLOB!",
              enforced: [{:origin, :generated}],
              unenforced: [{:key_size, 256}]
            }} =
             KM.generate_key(params, opts)

    assert_received {:sent, :generate_key, body}
    assert body == Message.generate_key(params)
  end

  test "begin maps the purpose atom and decodes handle plus output params" do
    out = ParamSet.encode([{:nonce, "iv"}])
    reply = <<0::little-signed-32, 42::little-64>> <> out
    opts = [transport: transport(%{begin: reply})]

    assert {:ok, %{op_handle: 42, output_params: [{:nonce, "iv"}]}} =
             KM.begin(:encrypt, "KEYBLOB", [{:padding, :none}], opts)

    assert_received {:sent, :begin, <<0::little-32, 7::little-32, "KEYBLOB", _::binary>>}
  end

  test "finish decodes output and surfaces a keymaster error" do
    reply = <<0::little-signed-32, 3::little-32, "CT!">> <> ParamSet.encode([])
    opts = [transport: transport(%{finish: reply})]
    assert {:ok, %{output: "CT!"}} = KM.finish(42, "pt", <<>>, [], opts)

    err = [transport: fn _r, _l -> {:ok, <<-30::little-signed-32>>} end]
    assert {:error, {:keymaster, -30}} = KM.finish(42, "pt", <<>>, [], err)
  end
end

defmodule QseeKeymaster.TransportDeviceTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster.Transport.Device

  test "a missing device is reported, not created" do
    path =
      Path.join(System.tmp_dir!(), "qseecom_raw_missing_#{System.unique_integer([:positive])}")

    assert {:error, :enoent} = Device.lookup(device: path)
    refute File.exists?(path)
  end

  test "a regular file is refused" do
    path =
      Path.join(System.tmp_dir!(), "qseecom_raw_regular_#{System.unique_integer([:positive])}")

    File.write!(path, "")
    assert {:error, {:not_a_device, :regular}} = Device.send(<<1, 2, 3>>, 16, device: path)
    File.rm!(path)
  end
end
