import numpy as np
from PIL import Image

def dilation(np_img, kernel, row_size, col_size):
    dilation_img =  np.zeros((row_size, col_size), dtype=int)
    for i in range(row_size):
        for j in range(col_size):
            max_value = 0
            for k in kernel:
                new_i = i - k[0]
                new_j = j - k[1]
                if new_i >= 0 and new_i < row_size and new_j >= 0 and new_j < col_size:
                    local_value = np_img[new_i][new_j] + k[2]
                    if max_value < local_value:
                        max_value = local_value
            dilation_img[i][j] = max_value
    return dilation_img

def erosion(np_img, kernel, row_size, col_size):
    erosion_img = np.zeros((row_size, col_size), dtype=int)
    for i in range(row_size):
        for j in range(col_size):
            min_value = 256
            for k in kernel:
                new_i = i + k[0]
                new_j = j + k[1]
                if new_i >= 0 and new_i < row_size and new_j >= 0 and new_j < col_size:
                    local_value = np_img[new_i][new_j] - k[2]
                    if local_value < min_value:
                        min_value = local_value
            if min_value < 0:
                min_value = 0
            erosion_img[i][j] = min_value
    return erosion_img



img = Image.open('lena.bmp')
np_img = np.array(img)

row_size = np_img.shape[0]
col_size = np_img.shape[1]

kernel = np.array( 
                [
                    [-2, -1,  0], [-2,  0,  0], [-2,  1,  0],
                    [-1, -2,  0], [-1, -1,  0], [-1,  0,  0], [-1,  1,  0], [-1,  2,  0],
                    [ 0, -2,  0], [ 0, -1,  0], [ 0,  0,  0], [ 0,  1,  0], [ 0,  2,  0],
                    [ 1, -2,  0], [ 1, -1,  0], [ 1,  0,  0], [ 1,  1,  0], [ 1,  2,  0],
                    [ 2, -1,  0], [ 2,  0,  0], [ 2,  1,  0]
                ])


np_dilation_img = dilation(np_img, kernel, row_size, col_size)
dilation_img = Image.fromarray(np.uint8(np_dilation_img))
dilation_img.save("Dilation.png")

np_erosion_img = erosion(np_img, kernel, row_size, col_size)
erosion_img = Image.fromarray(np.uint8(np_erosion_img))
erosion_img.save("Erosion.png")

np_opening_img = dilation(erosion(np_img, kernel, row_size, col_size), kernel, row_size, col_size)
opening_img = Image.fromarray(np.uint8(np_opening_img))
opening_img.save("Opening.png")

np_clsoing_img = erosion(dilation(np_img, kernel, row_size, col_size), kernel, row_size, col_size)
clsoing_img = Image.fromarray(np.uint8(np_clsoing_img))
clsoing_img.save("Closing.png")
