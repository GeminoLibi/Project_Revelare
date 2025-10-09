#!/usr/bin/env python3
"""
Fractal Encryption CLI for Project Revelare
Command-line interface for encrypting/decrypting files using fractal patterns
"""

import argparse
import sys
import os
import json
from pathlib import Path
from typing import Optional

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from revelare.utils.fractal_encryption import FractalEncryption
from revelare.utils.logger import get_logger

logger = get_logger(__name__)

def encrypt_file(input_file: str, output_file: Optional[str] = None,
                ifs_key: Optional[str] = None, generate_image: bool = False) -> bool:
    """
    Encrypt a file using fractal encryption.

    Args:
        input_file: Path to file to encrypt
        output_file: Output path for encrypted file (optional)
        ifs_key: IFS key string for custom encryption
        generate_image: Whether to generate fractal image

    Returns:
        Success status
    """
    try:
        # Check input file
        if not os.path.exists(input_file):
            print(f"❌ Error: Input file '{input_file}' does not exist")
            return False

        # Set up encryptor
        if ifs_key:
            try:
                transforms = FractalEncryption().get_ifs_from_string(ifs_key)
                encryptor = FractalEncryption(transforms)
                print(f"✅ Using custom IFS key with {len(transforms)} transforms")
            except Exception as e:
                print(f"❌ Error parsing IFS key: {e}")
                return False
        else:
            encryptor = FractalEncryption()
            print("✅ Using default Barnsley Fern IFS key")

        # Determine output file
        if not output_file:
            input_path = Path(input_file)
            output_file = str(input_path.parent / f"{input_path.stem}.fractal.json")

        print(f"🔐 Encrypting '{input_file}'...")
        print(f"📁 Output: '{output_file}'")

        # Read input file
        with open(input_file, 'rb') as f:
            file_data = f.read()

        print(f"📊 Input file size: {len(file_data):,} bytes")

        # Encrypt data
        def progress_callback(progress, status):
            print(f"\r🔄 {status}", end='', flush=True)

        encrypted_data = encryptor.encrypt_data(file_data, Path(input_file).name, progress_callback)
        print()  # New line after progress

        # Generate image if requested
        if generate_image:
            try:
                print("🎨 Generating fractal image...")
                image_data = encryptor.create_fractal_image(encrypted_data)
                image_file = Path(output_file).with_suffix('.png')
                with open(image_file, 'wb') as f:
                    f.write(image_data)
                print(f"✅ Image saved: '{image_file}'")
            except ImportError:
                print("⚠️  Image generation requires Pillow: pip install Pillow")
            except Exception as e:
                print(f"⚠️  Image generation failed: {e}")

        # Save encrypted data
        with open(output_file, 'w') as f:
            json.dump(encrypted_data, f, indent=2)

        print("✅ Encryption completed successfully!")
        print(f"🔢 Encrypted points: {len(encrypted_data['points']):,}")
        print(f"🗝️  IFS transforms used: {len(encrypted_data['ifs_key'])}")

        return True

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        logger.error(f"Fractal encryption error: {e}")
        return False

def decrypt_file(input_file: str, output_dir: Optional[str] = None,
                ifs_key: Optional[str] = None) -> bool:
    """
    Decrypt a fractal-encrypted file.

    Args:
        input_file: Path to encrypted fractal file
        output_dir: Directory to save decrypted file (optional)
        ifs_key: IFS key string for decryption

    Returns:
        Success status
    """
    try:
        # Check input file
        if not os.path.exists(input_file):
            print(f"❌ Error: Input file '{input_file}' does not exist")
            return False

        # Load encrypted data
        with open(input_file, 'r') as f:
            fractal_data = json.load(f)

        # Set up decryptor
        if ifs_key:
            try:
                transforms = FractalEncryption().get_ifs_from_string(ifs_key)
                decryptor = FractalEncryption(transforms)
                print(f"✅ Using custom IFS key with {len(transforms)} transforms")
            except Exception as e:
                print(f"❌ Error parsing IFS key: {e}")
                return False
        else:
            decryptor = FractalEncryption()
            print("✅ Using default Barnsley Fern IFS key")

        # Determine output directory
        if not output_dir:
            output_dir = Path(input_file).parent
        else:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

        print(f"🔓 Decrypting '{input_file}'...")
        print(f"📁 Output directory: '{output_dir}'")

        # Decrypt data
        def progress_callback(progress, status):
            print(f"\r🔄 {status}", end='', flush=True)

        decrypted_bytes, original_filename = decryptor.decrypt_data(fractal_data, progress_callback)
        print()  # New line after progress

        # Save decrypted file
        output_file = output_dir / original_filename
        with open(output_file, 'wb') as f:
            f.write(decrypted_bytes)

        print("✅ Decryption completed successfully!")
        print(f"📄 Original filename: '{original_filename}'")
        print(f"📊 Decrypted size: {len(decrypted_bytes):,} bytes")
        print(f"💾 Saved to: '{output_file}'")

        return True

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        logger.error(f"Fractal decryption error: {e}")
        return False

def generate_fractal_image(input_file: str, output_file: Optional[str] = None) -> bool:
    """
    Generate a fractal image from encrypted data.

    Args:
        input_file: Path to encrypted fractal file
        output_file: Output path for image (optional)

    Returns:
        Success status
    """
    try:
        # Check input file
        if not os.path.exists(input_file):
            print(f"❌ Error: Input file '{input_file}' does not exist")
            return False

        # Load encrypted data
        with open(input_file, 'r') as f:
            fractal_data = json.load(f)

        # Determine output file
        if not output_file:
            output_file = Path(input_file).with_suffix('.png')

        print(f"🎨 Generating fractal image from '{input_file}'...")
        print(f"🖼️  Output: '{output_file}'")

        # Generate image
        encryptor = FractalEncryption()
        image_data = encryptor.create_fractal_image(fractal_data)

        # Save image
        with open(output_file, 'wb') as f:
            f.write(image_data)

        print("✅ Fractal image generated successfully!")
        print(f"📏 Image size: {len(image_data):,} bytes")

        return True

    except ImportError:
        print("❌ Error: Image generation requires Pillow: pip install Pillow")
        return False
    except Exception as e:
        print(f"❌ Image generation failed: {e}")
        logger.error(f"Fractal image generation error: {e}")
        return False

def show_ifs_key(ifs_key: Optional[str] = None) -> None:
    """Display IFS key information."""
    if ifs_key:
        try:
            transforms = FractalEncryption().get_ifs_from_string(ifs_key)
            print(f"🔑 Custom IFS Key ({len(transforms)} transforms):")
            for i, t in enumerate(transforms):
                print(f"  w{i+1}: a={t.a}, b={t.b}, c={t.c}, d={t.d}, e={t.e}, f={t.f}")
        except Exception as e:
            print(f"❌ Error parsing IFS key: {e}")
    else:
        print("🔑 Default Barnsley Fern IFS Key:")
        default_ifs = FractalEncryption().get_ifs_key()
        for i, t in enumerate(default_ifs):
            print(f"  w{i+1}: a={t.a}, b={t.b}, c={t.c}, d={t.d}, e={t.e}, f={t.f}")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Fractal File Encryption - Hide files in fractal patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file
  python fractal_cli.py encrypt secret.txt

  # Encrypt with custom IFS key
  python fractal_cli.py encrypt secret.txt --ifs-key "w1: a=0.5, b=0, c=0, d=0.5, e=0, f=0"

  # Decrypt a file
  python fractal_cli.py decrypt secret.txt.fractal.json

  # Generate fractal image
  python fractal_cli.py image secret.txt.fractal.json

  # Show IFS key information
  python fractal_cli.py key --ifs-key "w1: a=0.5, b=0, c=0, d=0.5, e=0, f=0"
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file into fractal patterns')
    encrypt_parser.add_argument('input_file', help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_parser.add_argument('--ifs-key', help='Custom IFS key string')
    encrypt_parser.add_argument('--image', action='store_true', help='Generate fractal image')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a fractal-encrypted file')
    decrypt_parser.add_argument('input_file', help='Encrypted fractal file to decrypt')
    decrypt_parser.add_argument('-o', '--output-dir', help='Output directory')
    decrypt_parser.add_argument('--ifs-key', help='IFS key for decryption')

    # Image command
    image_parser = subparsers.add_parser('image', help='Generate fractal image from encrypted data')
    image_parser.add_argument('input_file', help='Encrypted fractal file')
    image_parser.add_argument('-o', '--output', help='Output image file path')

    # Key command
    key_parser = subparsers.add_parser('key', help='Show IFS key information')
    key_parser.add_argument('--ifs-key', help='IFS key to display (shows default if not provided)')

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        if args.command == 'encrypt':
            success = encrypt_file(
                args.input_file,
                args.output,
                args.ifs_key,
                args.image
            )

        elif args.command == 'decrypt':
            success = decrypt_file(
                args.input_file,
                args.output_dir,
                args.ifs_key
            )

        elif args.command == 'image':
            success = generate_fractal_image(
                args.input_file,
                args.output
            )

        elif args.command == 'key':
            show_ifs_key(args.ifs_key)
            return 0

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logger.error(f"CLI error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
