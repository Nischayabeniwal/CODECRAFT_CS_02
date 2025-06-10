def load_image(filepath):
    from PIL import Image
    return Image.open(filepath)

def save_image(image, filepath):
    image.save(filepath)

def image_to_pixels(image):
    return list(image.getdata())

def pixels_to_image(pixels, image_size):
    from PIL import Image
    return Image.new('RGB', image_size).putdata(pixels)