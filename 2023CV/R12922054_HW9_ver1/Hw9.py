import math
import numpy as np
from PIL import Image
import os 

def padding(np_img):
    row_size, col_size = np_img.shape
    
    targetImg = np.zeros((row_size + 2, col_size + 2), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    targetImg[0][0] = np_img[0][0]
    targetImg[0][targetImgCol_size - 1] = np_img[0][col_size - 1]
    targetImg[targetImgRow_size - 1][0] = np_img[row_size - 1][0]
    targetImg[targetImgRow_size - 1][targetImgCol_size - 1] = np_img[row_size - 1][col_size - 1]
    
    for j in range(1, targetImgCol_size - 1):
        targetImg[0][j] = np_img[0][j - 1]
        targetImg[targetImgRow_size - 1][j] = np_img[row_size - 1][j - 1]

    for i in range(1, targetImgRow_size - 1):
        targetImg[i][0] = np_img[i - 1][0]
        targetImg[i][targetImgCol_size - 1] = np_img[i - 1][col_size - 1]

    for i in range(1, targetImgRow_size - 1):
        for j in range(1, targetImgCol_size - 1):
            targetImg[i][j] = np_img[i - 1][j - 1]

    return targetImg

def robertPadding(np_img):
    row_size, col_size = np_img.shape

    targetImg = np.zeros((row_size + 1, col_size + 1), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    targetImg[targetImgRow_size - 1][targetImgCol_size - 1] = np_img[row_size - 1][col_size - 1]

    for j in range(targetImgCol_size - 1): 
        targetImg[targetImgRow_size - 1][j] = np_img[row_size - 1][j]

    for i in range(targetImgRow_size - 1):
        targetImg[i][targetImgCol_size - 1] = np_img[i][col_size - 1]

    for i in range(targetImgRow_size - 1):
        for j in range(targetImgCol_size - 1):
            targetImg[i][j] = np_img[i][j]

    return targetImg

def robertsOperator(np_img, threshold = 12):
    row_size = np_img.shape[0]
    col_size = np_img.shape[1]

    targetImg = np.zeros((row_size - 1, col_size - 1), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape
    
    r1_list = np.array([[0, 0, -1], [1, 1, 1]])
    r2_list = np.array([[0, 1, -1], [1, 0, 1]])

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            r1_sum = 0
            r2_sum = 0
            for r1 in r1_list:
                r1_sum += np_img[i + r1[0]][j + r1[1]] * r1[2]
            for r2 in r2_list:
                r2_sum += np_img[i + r2[0]][j + r2[1]] * r2[2]

            gradientMagnitude = math.sqrt((r1_sum ** 2) + (r2_sum ** 2))
            targetImg[i][j] = 0 if gradientMagnitude >= threshold else 255

    return targetImg

def generalOperator(np_img, threshold, mask1, mask2):
    row_size, col_size = np_img.shape

    targetImg = np.zeros((row_size - 2, col_size - 2), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):

            sum1 = 0
            sum2 = 0
            for element in mask1:
                sum1 += np_img[i + 1 + int(element[0])][j + 1 + int(element[1])] * element[2]
            for element in mask2:
                sum2 += np_img[i + 1 + int(element[0])][j + 1 + int(element[1])] * element[2]

            gradientMagnitude = math.sqrt((sum1 ** 2) + (sum2 ** 2))
            targetImg[i][j] = 0 if gradientMagnitude >= threshold else 255

    return targetImg

def prewittOperator(np_img, threshold = 24):
    prewittMask1 = np.array([
        [-1, -1, -1], [-1, 0, -1], [-1, 1, -1],
        [1, -1, 1], [1, 0, 1], [1, 1, 1],
    ])

    prewittMask2 = np.array([
        [-1, -1, -1], [-1, 1, 1],
        [0, -1, -1], [0, 1, 1],
        [1, -1, -1], [1, 1, 1],
    ])

    return generalOperator(np_img, threshold, prewittMask1, prewittMask2)

def sobelOperator(np_img, threshold = 38):
    sobelMask1 = np.array([
        [-1, -1, -1], [-1, 0, -2], [-1, 1, -1],
        [1, -1, 1], [1, 0, 2], [1, 1, 1],
    ])

    sobelMask2 = np.array([
        [-1, -1, -1], [-1, 1, 1],
        [0, -1, -2], [0, 1, 2],
        [1, -1, -1], [1, 1, 1],
    ])
    return generalOperator(np_img, threshold, sobelMask1, sobelMask2)

def freiAndChenOperator(np_img, threshold = 30):
    sqrt2 = math.sqrt(2)
    freiAndChenMask1 = np.array([
        [-1, -1, -1], [-1, 0, -sqrt2], [-1, 1, -1],
        [1, -1, 1], [1, 0, sqrt2], [1, 1, 1],
    ])

    freiAndChenMask2 = np.array([
        [-1, -1, -1], [-1, 1, 1],
        [0, -1, -sqrt2], [0, 1, sqrt2],
        [1, -1, -1], [1, 1, 1],
    ])
    return generalOperator(np_img, threshold, freiAndChenMask1, freiAndChenMask2)

def kirschCompassOperator(np_img, threshold = 135):
    KirschMask = np.array(
        [
            [
                [-1, -1, -3], [-1, 0, -3], [-1, 1, 5],
                [0, -1, -3], [0, 1, 5],
                [1, -1, -3], [1, 0, -3], [1, 1, 5],
            ],
            [
                [-1, -1, -3], [-1, 0, 5], [-1, 1, 5],
                [0, -1, -3], [0, 1, 5],
                [1, -1, -3], [1, 0, -3], [1, 1, -3],
            ],
            [
                [-1, -1, 5], [-1, 0, 5], [-1, 1, 5],
                [0, -1, -3], [0, 1, -3],
                [1, -1, -3], [1, 0, -3], [1, 1, -3],
            ],
            [
                [-1, -1, 5], [-1, 0, 5], [-1, 1, -3],
                [0, -1, 5], [0, 1, -3],
                [1, -1, -3], [1, 0, -3], [1, 1, -3],
            ],
            [
                [-1, -1, 5], [-1, 0, -3], [-1, 1, -3],
                [0, -1, 5], [0, 1, -3],
                [1, -1, 5], [1, 0, -3], [1, 1, -3],
            ],
            [
                [-1, -1, -3], [-1, 0, -3], [-1, 1, -3],
                [0, -1, 5], [0, 1, -3],
                [1, -1, 5], [1, 0, 5], [1, 1, -3],
            ],
            [
                [-1, -1, -3], [-1, 0, -3], [-1, 1, -3],
                [0, -1, -3], [0, 1, -3],
                [1, -1, 5], [1, 0, 5], [1, 1, 5],
            ],
            [
                [-1, -1, -3], [-1, 0, -3], [-1, 1, -3],
                [0, -1, -3], [0, 1, 5],
                [1, -1, -3], [1, 0, 5], [1, 1, 5],
            ],
        ]
    )
    row_size, col_size = np_img.shape

    targetImg = np.zeros((row_size - 2, col_size - 2), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            sumList = np.zeros(8, np.float64)
            for idx, k in enumerate(KirschMask):
                for element in k:
                    sumList[idx] += np_img[i + 1 + int(element[0])][j + 1 + int(element[1])] * element[2]
            gradientMagnitude = np.max(sumList)
            targetImg[i][j] = 0 if gradientMagnitude >= threshold else 255
    return targetImg

def RobinsonCompassOperator(np_img, threshold = 43):
    robinsonMask = np.array(
        [
            [
                [-1, -1, -1], [-1, 1, 1],
                [0, -1, -2], [0, 1, 2],
                [1, -1, -1], [1, 1, 1],
            ],
            [
                [-1, 0, 1], [-1, 1, 2],
                [0, -1, -1], [0, 1, 1],
                [1, -1, -2], [1, 0, -1],
            ],            [
                [-1, -1, 1], [-1, 0, 2], [-1, 1, 1],
                [1, -1, -1], [1, 0, -2], [1, 1, -1],
            ],
            [
                [-1, -1, 2], [-1, 0, 1],
                [0, -1, 1], [0, 1, -1],
                [1, 0, -1], [1, 1, -2],
            ]
        ]
    )
    row_size, col_size = np_img.shape

    targetImg = np.zeros((row_size - 2, col_size - 2), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):

            sumList = np.zeros(8, np.float64)
            for index, k in enumerate(robinsonMask):
                for element in k:
                    sumList[index] += np_img[i + 1 + int(element[0])][j + 1 + int(element[1])] * element[2]

            for index in range(4, 8):
                sumList[index] = -sumList[index - 4]

            gradientMagnitude = np.max(sumList)
            targetImg[i][j] = 0 if gradientMagnitude >= threshold else 255

    return targetImg

def nevatiaBabuOperator(np_img, threshold = 12500):
    nevatiaBabuMask = np.array(
        [
            [
                [-2, -2,  100], [-2, -1,  100], [-2, 0,  100], [-2, 1,  100], [-2, 2,  100],
                [-1, -2,  100], [-1, -1,  100], [-1, 0,  100], [-1, 1,  100], [-1, 2,  100],
                [ 0, -2,    0], [ 0, -1,    0], [ 0, 0,    0], [ 0, 1,    0], [ 0, 2,    0],
                [ 1, -2, -100], [ 1, -1, -100], [ 1, 0, -100], [ 1, 1, -100], [ 1, 2, -100],
                [ 2, -2, -100], [ 2, -1, -100], [ 2, 0, -100], [ 2, 1, -100], [ 2, 2, -100],
            ],
            [
                [-2, -2,  100], [-2, -1,  100], [-2, 0,  100], [-2, 1,  100], [-2, 2,  100],
                [-1, -2,  100], [-1, -1,  100], [-1, 0,  100], [-1, 1,   78], [-1, 2,  -32],
                [ 0, -2,  100], [ 0, -1,   92], [ 0, 0,    0], [ 0, 1,  -92], [ 0, 2, -100],
                [ 1, -2,   32], [ 1, -1,  -78], [ 1, 0, -100], [ 1, 1, -100], [ 1, 2, -100],
                [ 2, -2, -100], [ 2, -1, -100], [ 2, 0, -100], [ 2, 1, -100], [ 2, 2, -100],
            ],
            [
                [-2, -2,  100], [-2, -1,  100], [-2, 0,  100], [-2, 1,   32], [-2, 2, -100],
                [-1, -2,  100], [-1, -1,  100], [-1, 0,   92], [-1, 1,  -78], [-1, 2, -100],
                [ 0, -2,  100], [ 0, -1,  100], [ 0, 0,    0], [ 0, 1, -100], [ 0, 2, -100],
                [ 1, -2,  100], [ 1, -1,   78], [ 1, 0,  -92], [ 1, 1, -100], [ 1, 2, -100],
                [ 2, -2,  100], [ 2, -1,  -32], [ 2, 0, -100], [ 2, 1, -100], [ 2, 2, -100],
            ],
            [
                [-2, -2, -100], [-2, -1, -100], [-2, 0,    0], [-2, 1,  100], [-2, 2,  100],
                [-1, -2, -100], [-1, -1, -100], [-1, 0,    0], [-1, 1,  100], [-1, 2,  100],
                [ 0, -2, -100], [ 0, -1, -100], [ 0, 0,    0], [ 0, 1,  100], [ 0, 2,  100],
                [ 1, -2, -100], [ 1, -1, -100], [ 1, 0,    0], [ 1, 1,  100], [ 1, 2,  100],
                [ 2, -2, -100], [ 2, -1, -100], [ 2, 0,    0], [ 2, 1,  100], [ 2, 2,  100],
            ],
            [
                [-2, -2, -100], [-2, -1,   32], [-2, 0,  100], [-2, 1,  100], [-2, 2,  100],
                [-1, -2, -100], [-1, -1,  -78], [-1, 0,   92], [-1, 1,  100], [-1, 2,  100],
                [ 0, -2, -100], [ 0, -1, -100], [ 0, 0,    0], [ 0, 1,  100], [ 0, 2,  100],
                [ 1, -2, -100], [ 1, -1, -100], [ 1, 0,  -92], [ 1, 1,   78], [ 1, 2,  100],
                [ 2, -2, -100], [ 2, -1, -100], [ 2, 0, -100], [ 2, 1,  -32], [ 2, 2,  100],
            ],
            [
                [-2, -2,  100], [-2, -1,  100], [-2, 0,  100], [-2, 1,  100], [-2, 2,  100],
                [-1, -2,  -32], [-1, -1,   78], [-1, 0,  100], [-1, 1,  100], [-1, 2,  100],
                [ 0, -2, -100], [ 0, -1,  -92], [ 0, 0,    0], [ 0, 1,   92], [ 0, 2,  100],
                [ 1, -2, -100], [ 1, -1, -100], [ 1, 0, -100], [ 1, 1,  -78], [ 1, 2,   32],
                [ 2, -2, -100], [ 2, -1, -100], [ 2, 0, -100], [ 2, 1, -100], [ 2, 2, -100],
            ]
        ]
    )
    row_size, col_size = np_img.shape

    targetImg = np.zeros((row_size - 4, col_size - 4), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):

            sumList = np.zeros(len(nevatiaBabuMask), np.float64)
            for index, k in enumerate(nevatiaBabuMask):
                for element in k:
                    sumList[index] += np_img[i + 2 + int(element[0])][j + 2 + int(element[1])] * element[2]

            gradientMagnitude = np.max(sumList)
            targetImg[i][j] = 0 if gradientMagnitude >= threshold else 255
            
    return targetImg


path = './results'
if not os.path.isdir(path):
    os.mkdir(path)

img = Image.open('lena.bmp')
np_img = np.array(img, dtype = np.int64)

np_padding_img = padding(np_img)
np_2TimesPadding_img2= padding(np_padding_img)

# 12
robertPadding_img = robertPadding(np_img)
Roberts_img = robertsOperator(robertPadding_img, 12)
print("Roberts_img")
Image.fromarray(np.uint8(Roberts_img)).save('results/Roberts_img.png')

# 24
Prewitt_edge_detector_img = prewittOperator(np_padding_img, 24)
print("Prewitt_edge_detector_img")
Image.fromarray(np.uint8(Prewitt_edge_detector_img)).save('results/Prewitt_edge_detector_img.png')

# 38
Sobel_edge_detector_img = sobelOperator(np_padding_img, 38)
print("Sobel_edge_detector_img")
Image.fromarray(np.uint8(Sobel_edge_detector_img)).save('results/Sobel_edge_detector_img.png')

# 30
Frei_and_Chen_gradient_img = freiAndChenOperator(np_padding_img, 30)
print("Frei_and_Chen_gradient_img")
Image.fromarray(np.uint8(Frei_and_Chen_gradient_img)).save('results/Frei_and_Chen_gradient_img.png')

# 135
Kirsch_compass_img= kirschCompassOperator(np_padding_img, threshold = 135)
print("Kirsch_compass_img")
Image.fromarray(np.uint8(Kirsch_compass_img)).save('results/Kirsch_compass_img.png')

# 43
Robinson_compass_img= RobinsonCompassOperator(np_padding_img, threshold = 43)
print("Robinson_compass_img")
Image.fromarray(np.uint8(Robinson_compass_img)).save('results/Robinson_compass_img.png')

# 12500
Nevatia_Babu_img = nevatiaBabuOperator(np_2TimesPadding_img2, threshold = 12500)
print("Nevatia_Babu_img")
Image.fromarray(np.uint8(Nevatia_Babu_img)).save('results/Nevatia_Babu_img.png')


print("Finish")