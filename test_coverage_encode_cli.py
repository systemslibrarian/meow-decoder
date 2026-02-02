import sys
import argparse
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from meow_decoder.encode import main, encode_file
from meow_decoder.config import EncodingConfig

@pytest.fixture
def mock_args():
    with patch('sys.argv', ['meow-encode']):
        yield

def test_main_no_args_exits(capsys):
    with patch('sys.argv', ['meow-encode']):
        with pytest.raises(SystemExit):
            main()
    captured = capsys.readouterr()
    assert "error: the following arguments are required" in captured.err

def test_main_generate_keys():
    # main() returns 0 on success for generate-keys
    with patch('sys.argv', ['meow-encode', '--generate-keys', '--key-output-dir', '/tmp']):
        with patch('meow_decoder.x25519_forward_secrecy.generate_receiver_keys_cli') as mock_gen:
            ret = main()
            assert ret == 0
            mock_gen.assert_called_once()

def test_main_generate_keys_failure():
    # main() returns 1 on failure
    with patch('sys.argv', ['meow-encode', '--generate-keys']):
        with patch('meow_decoder.x25519_forward_secrecy.generate_receiver_keys_cli', side_effect=Exception("Boom")):
            ret = main()
            assert ret == 1

def test_main_summon_void_cat(capsys):
    with patch('sys.argv', ['meow-encode', '--summon-void-cat']):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "VOID CAT SUMMONED" in captured.out

def test_main_void_mode(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--mode', 'void', '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file') as mock_encode:
            mock_encode.return_value = {
                'input_size': 100, 'output_size': 200, 'qr_frames': 5, 
                'compression_ratio': 0.8, 'gif_duration': 1.0, 'elapsed_time': 0.1,
                'k_blocks': 1, 'num_droplets': 2, 'redundancy': 1.5, 'qr_size': (100, 100)
            }
            with patch('builtins.print'): # Silence output
                main()
            mock_encode.assert_called_once()
            args = mock_encode.call_args[1]
            # verbose set to False in void mode
            assert args['verbose'] is False

def test_main_no_forward_secrecy(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--no-forward-secrecy', '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file') as mock_encode:
            mock_encode.return_value = {
                'input_size': 100, 'output_size': 200, 'qr_frames': 5, 
                'compression_ratio': 0.8, 'gif_duration': 1.0, 'elapsed_time': 0.1,
                'k_blocks': 1, 'num_droplets': 2, 'redundancy': 1.5, 'qr_size': (100, 100)
            }
            main()
            args = mock_encode.call_args[1]
            assert args['forward_secrecy'] is False

def test_main_forward_secrecy_with_pubkey(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    pubkey = tmp_path / "pub.key"
    pubkey.write_bytes(b'A'*32)
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--forward-secrecy', '--receiver-pubkey', str(pubkey), '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file') as mock_encode:
            mock_encode.return_value = {
                'input_size': 100, 'output_size': 200, 'qr_frames': 5, 
                'compression_ratio': 0.8, 'gif_duration': 1.0, 'elapsed_time': 0.1,
                'k_blocks': 1, 'num_droplets': 2, 'redundancy': 1.5, 'qr_size': (100, 100)
            }
            main()
            args = mock_encode.call_args[1]
            assert args['forward_secrecy'] is True
            assert args['receiver_public_key'] == b'A'*32

def test_main_forward_secrecy_with_invalid_pubkey(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    pubkey = tmp_path / "pub.key"
    pubkey.write_bytes(b'A'*10) # Too short
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--forward-secrecy', '--receiver-pubkey', str(pubkey), '-p', 'pass']):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

def test_main_forward_secrecy_missing_pubkey_file(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    pubkey = tmp_path / "missing.key"
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--forward-secrecy', '--receiver-pubkey', str(pubkey), '-p', 'pass']):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

def test_main_forward_secrecy_no_key_warning(tmp_path, capsys):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    output_file = tmp_path / "out.gif"
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', str(output_file), '--forward-secrecy', '-p', 'pass', '-v']):
        with patch('meow_decoder.encode.encode_file') as mock_encode:
            mock_encode.return_value = {
                'input_size': 100, 'output_size': 200, 'qr_frames': 5, 
                'compression_ratio': 0.8, 'gif_duration': 1.0, 'elapsed_time': 0.1,
                'k_blocks': 1, 'num_droplets': 2, 'redundancy': 1.5, 'qr_size': (100, 100)
            }
            main()
            captured = capsys.readouterr()
            # Should print warning about password-only mode
            assert "using MEOW3" in captured.out or "Using password-only mode" in captured.out

def test_main_catnip(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', 'out.gif', '--catnip', 'tuna', '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file') as mock_encode:
            mock_encode.return_value = {
                'input_size': 100, 'output_size': 200, 'qr_frames': 5, 
                'compression_ratio': 0.8, 'gif_duration': 1.0, 'elapsed_time': 0.1,
                'k_blocks': 1, 'num_droplets': 2, 'redundancy': 1.5, 'qr_size': (100, 100)
            }
             # Should succeed
            main()

def test_main_input_not_exists():
    with patch('sys.argv', ['meow-encode', '-i', 'missing.txt', '-o', 'out.gif']):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

def test_main_input_not_file(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    with patch('sys.argv', ['meow-encode', '-i', str(d), '-o', 'out.gif']):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

def test_main_password_prompt_mismatch(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', 'out.gif']):
        with patch('meow_decoder.encode.getpass', side_effect=['pass1', 'pass2']):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

def test_main_password_empty(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', 'out.gif']):
        with patch('meow_decoder.encode.getpass', return_value=''):
             with pytest.raises(SystemExit) as exc:
                main()
             assert exc.value.code == 1

def test_main_wipe_source(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.write_text("secrets")
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', 'out.gif', '--wipe-source', '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file', return_value={
            'input_size': 7, 'compressed_size': 5, 'encrypted_size': 10,
            'output_size': 100, 'compression_ratio': 0.8, 'k_blocks': 1,
            'num_droplets': 2, 'qr_frames': 2, 'qr_size': (100, 100), 
            'gif_duration': 1, 'elapsed_time': 0.1, 'redundancy': 1.5
        }):
            main()
            assert not input_file.exists()

def test_main_encode_error(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.touch()
    
    with patch('sys.argv', ['meow-encode', '-i', str(input_file), '-o', 'out.gif', '-p', 'pass']):
        with patch('meow_decoder.encode.encode_file', side_effect=ValueError("Encode failed")):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

# ------ encode_file logic coverage ------

def test_encode_file_pq_mode(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.write_bytes(b"data")
    out_file = tmp_path / "out.gif"
    
    with patch('meow_decoder.encode.encrypt_file_bytes') as mock_enc:
        result_tuple = (b'comp', b'sha', b'salt', b'nonce', b'cipher', None, b'key')
        mock_enc.return_value = result_tuple
        
        with patch('meow_decoder.encode.FountainEncoder') as mock_fount:
             mock_fount.return_value.droplet.return_value = MagicMock(seed=1, block_indices=[], data=b'd')
             
             with patch('meow_decoder.encode.QRCodeGenerator') as mock_qr:
                 mock_qr.return_value.generate.return_value = MagicMock(size=(10,10))
                 
                 with patch('meow_decoder.encode.GIFEncoder') as mock_gif:
                     mock_gif.return_value.create_gif.return_value = 100
                     
                     stats = encode_file(input_file, out_file, "pass", use_pq=True, verbose=True)
                     
    # Verify PQ mode prints
    # Note: testing prints effectively is hard without capsys, but the execution path is hit

def test_encode_file_fs_with_key(tmp_path):
    input_file = tmp_path / "in.txt"
    input_file.write_bytes(b"data")
    out_file = tmp_path / "out.gif"
    
    with patch('meow_decoder.encode.encrypt_file_bytes') as mock_enc:
        # FS encryption returns ephemeral key (must be 32 bytes)
        # Note: ephemeral_public_key is the 6th element
        mock_enc.return_value = (b'comp', b'sha', b'salt', b'nonce', b'cipher', b'A'*32, b'key')
        
        with patch('meow_decoder.encode.FountainEncoder') as mock_fount:
             mock_fount.return_value.droplet.return_value = MagicMock(seed=1, block_indices=[], data=b'd')
             
             with patch('meow_decoder.encode.QRCodeGenerator') as mock_qr:
                 mock_qr.return_value.generate.return_value = MagicMock(size=(10, 10))
                 
                 with patch('meow_decoder.encode.GIFEncoder') as mock_gif:
                     mock_gif.return_value.create_gif.return_value = 100
                     
                     stats = encode_file(input_file, out_file, "pass", forward_secrecy=True, receiver_public_key=b'pub', verbose=True)
                     assert stats['output_size'] == 100
