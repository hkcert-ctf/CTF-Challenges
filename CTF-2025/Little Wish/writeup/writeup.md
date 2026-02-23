# Writeup - Little Wish

This challenge involves several examination points, all centered on the attached GIF file, including **GIF file header repair** (requiring participants to be familiar with the GIF file header and the subsequent 3-byte version identifiers "87a" and "89a"), **GIF frame delay steganography** and **frame extraction**. It also covers the differences between **palette-mode** and RGB-mode images, **LSB steganography on the color palette** in palette mode, as well as **Deep Sound audio steganography**.

------

Unzipping the attachment yields two files: **小小心願，深沉的聲響.wav** (A Little Wish, Profound Sound.wav) and **tellme.gift**.

First, check the audio file—it is a song, and "小小心願 (A Little Wish)" is actually a cryptic translation of the song's title. The phrase "深沉的聲響 (Profound Sound)" can be associated with **Deep Sound** (in fact, running it through a translation tool will also give this English term, which is easy to find with a quick search). Opening the audio file in Deep Sound will reveal that a password is required.

Next, examine the file **tellme.gift**. Open it with 010 Editor and you will find the **file header is corrupted**. The standard GIF file header starts with GIF89a or GIF87a—simply repair the character `t` to `8` (corresponding to changing 0x54 to 0x38), and you will confirm that this is a valid GIF file.

> Additionally, careful participants will notice that a compressed package is attached to the end of the file, containing several hints:
>
> 
>
> 1. The first hint indicates that the GIF89a version has a frame duration setting that the GIF87a version lacks.
> 2. The second hint prompts to look for an image in "P" mode (i.e., palette mode in PIL), suggesting that the secret information is hidden in the color palette—though participants need to realize they must extract the frames from the GIF first.
> 3. The third hint states that the GIF and steganography were created using the PIL library, and it is best to use this library to write a decryption script.
>
> 
>
> There is also a vertical message at the bottom: **？Anything else？**—this is actually a prompt to read the three lines of text above **vertically**, as the first characters of the three sentences form the acronym **LSB** (this was also planned to be released as a hint during the competition).

Open the repaired GIF file: it shows a small goldfish shaking its head slowly. If participants notice the slight differences in frame delay between the frames of the goldfish GIF, they should infer that this is **frame delay steganography**—this is a point that relies on prior knowledge accumulation.

------

There are several methods to extract the frame duration from a GIF:

### 1 (Fastest)

Run the following command in a Linux system:

shell

```
identify -format "%s %T \n" tellme.gif
```

The direct output is:

plaintext

```
0 77
1 69
2 78
3 71
4 77
5 69
6 78
7 71
8 95
9 88
10 73
11 65
12 78
13 71
```

### 2

Modify the GIF template in 010 Editor to view the frame duration (refer to online tutorials for the specific method). A relevant reference is attached below:

[CTF—GIF File Format, Steganography Methods and Cases](https://blog.csdn.net/weixin_41905135/article/details/140987886)

###  3

Manually write a script to extract the duration using the PIL library in Python. The sample code is provided below:

python

```
from PIL import Image, ImageSequence
import os

def extract_hidden_text(gif_path):
    img = Image.open(gif_path)
    text = ""

    for frame in ImageSequence.Iterator(img):
        delay = frame.info.get('duration', 100) // 10
        print(f"Frame Delay: {delay}")
        # The delay value directly corresponds to ASCII code
        if 32 <= delay <= 126:  # Printable character range
            text += chr(delay)
        else:
            text += "?"  # Non-printable character

    return text

if __name__ == "__main__":
    hidden_text = extract_hidden_text("password.gif")  # Modify the path if the script is not in the same directory as the GIF
    print(f"Text extracted from GIF: {hidden_text}")
```

### 4 (The Most Tricky)

If you play Arknights, recognize that the goldfish and this song correspond to the operator Haruka, know her real name is Yuzuru Momoka, happen to guess that the extracted text is the pinyin of Momoka, accidentally input it in all uppercase, and casually add an underscore between the second "MENG" and "XIANG"—then you win. The final extracted text is **MENGMENG_XIANG**.

After extracting the numerical values, participants also need to realize that these values correspond to **ASCII codes**.

------

With this text string, attempt to open **深沉的聲響.wav** in Deep Sound and enter the password—it will be verified as correct, and an encrypted compressed package will be extracted (the password for the package is unknown).

Recall the previous hints, and you should realize there is additional information hidden in the GIF. At this point, you need to extract each frame for analysis. Using PIL, you will find that the **first frame is a P-mode (palette) image**, different from the others. Combining the principle of LSB steganography, you can infer that the hidden text is steganographed in the **least significant bit (LSB)** of the three channel values of each preset color in the palette.

> # What is a Color Palette?
>
> 
>
> The color palette is stored near the file header of an image file—detailed information is available online.
>
> 
>
> First, take the familiar RGB image as an example: RGB images typically do not use a palette for color storage. Instead, they use three channels (R, G, B), with each channel storing the corresponding color value (0~255) as 1 byte (8 bits) at each pixel position. For example, a pure red image has a value of 255 for every pixel in the R channel (indicating the maximum "red intensity"), and 0 for the other two channels (indicating no component of those colors).
>
> 
>
> An **important advantage** of using a color palette is: **reducing storage space usage**.
>
> Simply put, a color palette is a preset **table** that can store up to 256 different **color schemes**, each defined by an RGB value.
>
> 
>
> The following code prints the palette of an image `img`, formatted as 256 color schemes × 3 channel values:
>
> 
>
> python
>
> 
>
> 运行
>
> 
>
> 
>
> 
>
> 
>
> ```
> print(np.array(img.getpalette()).reshape(256,3))
> ```
>
> 
>
> In contrast, images using a palette are stored in a single channel—each pixel position stores an **index** in the palette table. This reduces the storage space requirement from 3 bytes (for RGB) to **1 byte** per pixel.
>
> 
>
> Of course, the number of usable colors is limited by the maximum number of color schemes in the table (256)—this is a **disadvantage** of P-mode images.
>
> (The above information is from online sources)

------

Based on all the above information, we can start writing the extraction script.

The sample script is provided below:

python



运行









```
from PIL import Image
from Crypto.Util.number import *

def extractFrames_P(input_file) -> list[Image.Image]:
    # Load the GIF
    gif = Image.open(input_file)

    # Extract frames
    frames = []
    try:
        while True:
            frames.append(gif.copy())
            gif.seek(len(frames))
    except EOFError:
        pass

    return frames

def extract_time_delay(gif_path):
    img = Image.open(gif_path)

    # Extract duration
    delays = []
    frames = []
    try:
        for i in range(14):
            img.seek(i)
            frames.append(img.copy())
            delay = img.info.get('duration', 0)
            delays.append(delay)
    except:
        pass

    time_text = ''.join(chr(delay // 10) for delay in delays if delay > 0)

    return time_text

def extract_palette_data(input_frame:Image.Image):
    im = input_frame

    # print(im.mode)
    im_palette = im.getpalette()

    # print("get palette:", im_palette)
    # Extract hidden data
    m = ""
    for i in range(0, len(im_palette)):
        m += bin(im_palette[i])[-1]
    # print("extracted bin msg：", m)
    return long_to_bytes(int(m, 2)).decode()

if __name__ == "__main__":
    frames = extractFrames_P("tellme.gif")
    res1 = extract_time_delay("tellme.gif")
    res2 = extract_palette_data(frames[0])
    print("From time delay extracted:\n", res1)
    print("From palette extracted:\n", res2)
```

Finally, the hidden information is extracted: **pwd:The_Operator_I_Failed_To_Get_After_237_Pulls**

(TAT)

------

Enter this password to unlock the compressed package, and the final flag is obtained: **flag{1Ch1B4n_SuK1_N4_W4t4sh1_N1N4RuN0~}**

> *一番好きな私になるの～*
>
> (English translation: Becoming the version of myself that I love the most~)
