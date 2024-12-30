import numpy as np
import copy
from PIL import Image

def open_img_file(path):
    img = Image.open(path)

    return img

def upside_dowm(original_img, r_size, c_size):
    copy_img = copy.deepcopy(original_img)
    for i in range (int(r_size/2)):
        for j in range (c_size):
            tmp_img = copy_img[i][j]
            copy_img[i][j] = copy_img[r_size-1-i][j]
            copy_img[r_size-1-i][j] = tmp_img
    
    result = Image.fromarray(copy_img)
    return  result
             
            
def rightside_left(original_img, r_size, c_size):
    copy_img = copy.deepcopy(original_img)
    for i in range ((r_size)):
        for j in range (int(c_size/2)):
            tmp_img = copy_img[i][j]
            copy_img[i][j] = copy_img[i][c_size-1-j]
            copy_img[i][c_size-1-j] = tmp_img

    result = Image.fromarray(copy_img)
    return  result

def diagonally_flip(original_img, r_size, c_size):
    copy_img = copy.deepcopy(original_img)
    for i in range (r_size):
        for j in range (c_size-i):
            tmp_img = copy_img[i][j]
            copy_img[i][j] = copy_img[c_size-1-j][r_size-1-i]
            copy_img[c_size-1-j][r_size-1-i] = tmp_img

    result = Image.fromarray(copy_img)
    return  result


def rotate(original_img, degree):
    copy_img = copy.deepcopy(original_img)
    result = copy_img.rotate(degree)

    return  result

def shrink(original_img, r_size, c_size):
    copy_img = copy.deepcopy(original_img)
    result = copy_img.resize( (int(r_size/2), int(c_size/2)) )

    return  result

def binarize(original_img, r_size, c_size):
    copy_img = copy.deepcopy(original_img)
    for i in range (r_size):
        for j in range(c_size):
            copy_img[i][j] = 255 if(copy_img[i][j] > 128) else 0
    
    result = Image.fromarray(copy_img)
    return  result

original_img = open_img_file("lena.bmp")
numpy_original_img = np.array(original_img)
row_size = numpy_original_img.shape[0]
col_size = numpy_original_img.shape[1]


upside_dowm_img = upside_dowm(numpy_original_img, row_size, col_size)
upside_dowm_img.save("result-upside_down_img.bmp")

rightside_left_img = rightside_left(numpy_original_img, row_size, col_size)
rightside_left_img.save("result-rightside_left_img.bmp")

diagonally_flip_img = diagonally_flip(numpy_original_img, row_size, col_size)
diagonally_flip_img.save("result-diagonally_flip_img.bmp")

degree = 45
rotate_img = rotate(original_img, degree)
rotate_img.save("result-rotate_img.bmp")

shrink_img = shrink(original_img, row_size, col_size)
shrink_img.save("result-shrink_img.bmp")

binarize_img = binarize(numpy_original_img, row_size, col_size)
binarize_img.save("result-binarize_img.bmp")