from PIL import Image, ImageDraw
import binascii

# Constants
width, height = 480, 360
square_size = 20
center_x = 0
center_y = 0

def chr2bin(c):
    return '{:08b}'.format(min(ord(c), 255)) # prevent > 255 values

def translate(x, y):
    # Adjust input coordinates (convert from origin in the middle to top-left origin)
    canvas_center_x = width // 2
    canvas_center_y = height // 2 - 1 # scratch... why do this to me... -1...
    adjusted_x = canvas_center_x + x
    adjusted_y = canvas_center_y - y  # Invert Y-axis to match drawing convention

    return (adjusted_x, adjusted_y)

def eread(filename):
    # Create a blank image with a white background
    # img = Image.new('RGB', (width, height), 'white')
    img = Image.open(filename)
    text_in_binary = ''

    def read_px(x, y):
        px = img.getpixel(translate(x, y))[:3] # handle both RGB and RGBA images
        if px == (255, 255, 255):
            raise Exception('EOF')
        if px == (0, 0, 255):
            return '0'
        if px == (255, 0, 0):
            return '1'
        
    
    ## main draw
    r = 24
    p = 1
    try: 
        while True:
            i = r * -1
            for _ in range(r * 2 + 1): # correct?
                y = i
                x1 = abs(y) - r
                x2 = r - abs(y)

                text_in_binary = text_in_binary + read_px(x1, y)
                p += 1
                if not (x1 == x2):
                    text_in_binary = text_in_binary + read_px(x2, y)
                    p += 1
                i += 1
            r += 1
    except Exception as e:
        # print(e)
        pass
    
    # to keep the square intact, there would be 0 paddings after EOF which makes the bit
    # not dividable by 8
    return binascii.unhexlify('%x' % int(text_in_binary[:-(len(text_in_binary)%8)], 2))

if __name__ == '__main__':
    file_count = 500
    text = b''
    for i in range(1, file_count + 1):
        text += eread("gen/{}.png".format(i))
    print(text)