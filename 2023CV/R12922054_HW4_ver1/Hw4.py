import copy
import numpy as np
from PIL import Image

def dilation(np_img, kernel, row_size, col_size):
    dilation_img =  np.zeros((row_size, col_size), dtype=int)
    for i in range(row_size):
        for j in range(col_size):
            if np_img[i][j]:
                for k in kernel:
                    new_i = i + k[0]
                    new_j = j + k[1]
                    if new_i >= 0 and new_i < row_size and new_j >= 0 and new_j < col_size:
                        dilation_img[new_i][new_j] = 255
    return dilation_img

def erosion(np_img, kernel, row_size, col_size):
    erosion_img = np.zeros((row_size, col_size), dtype=int)
    for i in range(row_size):
        for j in range(col_size):
            flag = True
            for k in kernel:
                new_i = i + k[0]
                new_j = j + k[1]
                if new_i < 0 or new_i >= row_size or new_j < 0 or new_j >= col_size or not np_img[new_i][new_j]:
                    flag = False
                    break
            if flag == True:
                erosion_img[i][j] = 255
    return erosion_img

def get_complement(np_img, row_size, col_size):
    complement_img = copy.deepcopy(np_img)
    for i in range(row_size):
        for j in range(col_size):
            complement_img[i][j] = 255 - np_img[i][j]
    return complement_img

def hit_and_miss(np_img, kernel_j, kernel_k, row_size, col_size):
    origin_img = copy.deepcopy(np_img)
    origin_img_complement = get_complement(origin_img, row_size, col_size)
    j_kernel_img  = erosion(origin_img, kernel_j, row_size, col_size)
    k_kernel_img = erosion(origin_img_complement, kernel_k, row_size, col_size)


    hit_and_miss_img = copy.deepcopy(np_img)
    for i in range(row_size):
        for j in range(col_size):
            if j_kernel_img[i][j] and k_kernel_img[i][j]:
                hit_and_miss_img[i][j] = 255
            else:
                hit_and_miss_img[i][j] = 0
    return hit_and_miss_img


img = Image.open('lena.bmp')
np_img = np.array(img)

row_size = np_img.shape[0]
col_size = np_img.shape[1]


for i in range(row_size):
    for j in range(col_size):
        np_img[i][j] = 255 if(np_img[i][j] >= 128) else 0

kernel = np.array(  [   [-2, -1], [-2,  0], [-2,  1],
                        [-1, -2], [-1, -1], [-1,  0], [-1,  1], [-1,  2],
                        [ 0, -2], [ 0, -1], [ 0,  0], [ 0,  1], [ 0,  2],
                        [ 1, -2], [ 1, -1], [ 1,  0], [ 1,  1], [ 1,  2],
                        [ 2, -1], [ 2,  0], [ 2,  1],
                    ])

kernel_j = np.array([   [ 0, -1], [ 0,  0], [1,  0],
                    ])
kernel_k = np.array([   [-1,  0], [-1,  1], [0,  1]
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

np_hit_and_miss_img = hit_and_miss(np_img, kernel_j, kernel_k, row_size, col_size)
hit_and_miss_img = Image.fromarray(np.uint8(np_hit_and_miss_img))
hit_and_miss_img.save("Hit_and_miss.png")