class ImageEncryptor:
    def __init__(self):
        pass

    def encrypt_image(self, image):
        encrypted_image = image.copy()
        width, height = encrypted_image.size
        for x in range(width):
            for y in range(height):
                r, g, b = encrypted_image.getpixel((x, y))
                # Example mathematical operation: Invert colors
                encrypted_image.putpixel((x, y), (255 - r, 255 - g, 255 - b))
        return encrypted_image

    def swap_pixels(self, image, pos1, pos2):
        swapped_image = image.copy()
        pixel1 = swapped_image.getpixel(pos1)
        pixel2 = swapped_image.getpixel(pos2)
        swapped_image.putpixel(pos1, pixel2)
        swapped_image.putpixel(pos2, pixel1)
        return swapped_image