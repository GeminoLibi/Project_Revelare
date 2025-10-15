# fractal_encryption.py
# A command-line tool for fractal steganography.
# Author: Gemini, in collaboration with Markus.
# Project: Revelare

import numpy as np
from PIL import Image
import argparse
import sys
import cmath

# --- Constants ---
# Using a unique, multi-byte delimiter to minimize collision probability with actual data.
MESSAGE_DELIMITER = b"<-REVELARE_END->"

def parse_complex(s: str) -> complex:
    """Parses a string like '0.285+0.01j' into a complex number."""
    try:
        return complex(s.replace(' ', ''))
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid complex number format: '{s}'. Use 'a+bj' format.")

def generate_julia_set(width: int, height: int, c: complex, max_iter: int) -> np.ndarray:
    """
    Generates iteration counts for a Julia set for a given complex constant 'c'.
    """
    x = np.linspace(-1.5, 1.5, width)
    y = np.linspace(-1.5, 1.5, height)
    z = x[np.newaxis, :] + y[:, np.newaxis] * 1j
    
    iterations = np.zeros(z.shape, dtype=int)
    mask = np.full(z.shape, True, dtype=bool)

    for i in range(max_iter):
        z[mask] = z[mask] * z[mask] + c
        diverged = np.abs(z) > 2
        
        # Store iteration count for newly diverged points
        newly_diverged = diverged & mask
        iterations[newly_diverged] = i
        
        # Update mask to exclude diverged points from future calculations
        mask &= ~diverged
    
    # Set max_iter for points that never diverged (part of the set)
    iterations[mask] = max_iter
    
    return iterations

def colorize_fractal(iterations: np.ndarray, max_iter: int) -> np.ndarray:
    """
    Applies a smooth coloring algorithm to the fractal iteration data.
    Returns a (height, width, 3) numpy array of RGB values.
    """
    height, width = iterations.shape
    img_array = np.zeros((height, width, 3), dtype=np.uint8)

    # Use a vectorized approach for coloring
    mask_in_set = iterations == max_iter
    mask_outside_set = ~mask_in_set

    # Color points outside the set based on iteration count
    if np.any(mask_outside_set):
        iters_outside = iterations[mask_outside_set]
        # These coefficients create a pleasing blue/purple/yellow palette
        r = (9 * (1 - np.cos(iters_outside * 0.09)) * 127.5).astype(np.uint8)
        g = (9 * (1 - np.cos(iters_outside * 0.05)) * 127.5).astype(np.uint8)
        b = (9 * (1 - np.cos(iters_outside * 0.03)) * 127.5).astype(np.uint8)
        img_array[mask_outside_set] = np.stack([r, g, b], axis=-1)

    # Points inside the set are colored black
    img_array[mask_in_set] = [0, 0, 0]
    
    return img_array

def embed_data(image_array: np.ndarray, data: bytes) -> np.ndarray:
    """
    Embeds binary data into the least significant bit (LSB) of the blue channel of an image array.
    """
    data_with_delimiter = data + MESSAGE_DELIMITER
    data_bits = ''.join(f"{byte:08b}" for byte in data_with_delimiter)
    
    num_bits = len(data_bits)
    max_capacity = image_array.shape[0] * image_array.shape[1]
    
    if num_bits > max_capacity:
        raise ValueError(f"Data is too large to embed. Maximum capacity: {max_capacity // 8} bytes. Data size: {len(data)} bytes.")

    # Create a mutable copy
    stego_array = image_array.copy()
    
    # Flatten the array for easier iteration
    flat_pixels = stego_array.reshape(-1, 3)
    
    for i in range(num_bits):
        bit = int(data_bits[i])
        # Modify the blue channel (index 2)
        # Clear the LSB and then set it if bit is 1
        flat_pixels[i, 2] = (flat_pixels[i, 2] & 0b11111110) | bit
        
    return stego_array

def extract_data(image_array: np.ndarray) -> bytes:
    """
    Extracts data hidden in the LSB of the blue channel until a delimiter is found.
    """
    flat_pixels = image_array.reshape(-1, 3)
    
    extracted_bits = []
    delimiter_bits = ''.join(f"{byte:08b}" for byte in MESSAGE_DELIMITER)
    delimiter_len = len(delimiter_bits)

    for pixel in flat_pixels:
        # Extract the LSB from the blue channel
        extracted_bits.append(str(pixel[2] & 1))
        
        # Check if the end of the bitstream matches the delimiter
        if len(extracted_bits) >= delimiter_len:
            if ''.join(extracted_bits[-delimiter_len:]) == delimiter_bits:
                # Delimiter found, remove it from the bitstream and break
                all_bits = ''.join(extracted_bits[:-delimiter_len])
                break
    else:
        # Loop finished without finding the delimiter
        raise ValueError("Message delimiter not found. The image may not contain data or is corrupted.")

    # Convert bit string to bytes
    byte_array = bytearray()
    for i in range(0, len(all_bits), 8):
        byte_str = all_bits[i:i+8]
        if len(byte_str) == 8: # Avoid incomplete bytes
            byte_array.append(int(byte_str, 2))
            
    return bytes(byte_array)

def main():
    """Main function to handle command-line arguments and operations."""
    parser = argparse.ArgumentParser(
        description="Revelare: A tool for steganography using Julia set fractals.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Available modes")
    
    # --- ENCRYPT MODE ---
    parser_encrypt = subparsers.add_parser("encrypt", help="Embed a file into a fractal image.")
    parser_encrypt.add_argument("input_file", help="Path to the file containing the secret message.")
    parser_encrypt.add_argument("output_image", help="Path to save the output PNG image.")
    parser_encrypt.add_argument("-k", "--key", type=parse_complex, default="-0.8+0.156j",
                                help="The complex constant 'c' for the Julia set (e.g., '-0.4+0.6j').")
    parser_encrypt.add_argument("-W", "--width", type=int, default=1920, help="Width of the image.")
    parser_encrypt.add_argument("-H", "--height", type=int, default=1080, help="Height of the image.")
    parser_encrypt.add_argument("-i", "--iterations", type=int, default=300, help="Max iterations for fractal generation.")

    # --- DECRYPT MODE ---
    parser_decrypt = subparsers.add_parser("decrypt", help="Extract a secret message from an image.")
    parser_decrypt.add_argument("input_image", help="Path to the steganographic PNG image.")
    parser_decrypt.add_argument("-o", "--output_file", help="Optional: Path to save the extracted data. Defaults to stdout.")

    args = parser.parse_args()
    
    try:
        if args.mode == "encrypt":
            print(f"[*] Reading data from '{args.input_file}'...")
            with open(args.input_file, 'rb') as f:
                data_to_embed = f.read()

            print(f"[*] Generating Julia set (c={args.key}, {args.width}x{args.height}, {args.iterations} iter)...")
            fractal_iters = generate_julia_set(args.width, args.height, args.key, args.iterations)
            
            print("[*] Colorizing fractal...")
            base_image_array = colorize_fractal(fractal_iters, args.iterations)
            
            print(f"[*] Embedding {len(data_to_embed)} bytes of data...")
            stego_image_array = embed_data(base_image_array, data_to_embed)

            print(f"[*] Saving steganographic image to '{args.output_image}'...")
            Image.fromarray(stego_image_array).save(args.output_image)
            print("[+] Encryption complete.")

        elif args.mode == "decrypt":
            print(f"[*] Loading image '{args.input_image}'...")
            with Image.open(args.input_image) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                image_array = np.array(img)

            print("[*] Extracting hidden data...")
            extracted_data = extract_data(image_array)

            if args.output_file:
                print(f"[*] Writing {len(extracted_data)} bytes to '{args.output_file}'...")
                with open(args.output_file, 'wb') as f:
                    f.write(extracted_data)
                print("[+] Decryption complete.")
            else:
                print("\n--- EXTRACTED DATA ---")
                # Write bytes directly to stdout buffer to handle any encoding
                sys.stdout.buffer.write(extracted_data)
                print("\n----------------------")
                print("[+] Decryption complete.")

    except (ValueError, FileNotFoundError, argparse.ArgumentTypeError) as e:
        print(f"\n[!] ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()