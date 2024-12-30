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


def getZeroCrossingKernel(size = 1):
    zeroCrossingKernel = []

    roundStart = -size
    roundEnd = size + 1
    for i in range(roundStart, roundEnd):
        for j in range(roundStart, roundEnd):
            if i == 0 and j == 0:
                continue
            zeroCrossingKernel.append([i, j])

    return np.array(zeroCrossingKernel)

def getLaplacianImg(np_img, threshold, kernel, kernalScale = 1, kernalSize = 3):
    kernalShift = kernalSize // 2
    kernalPadding = kernalShift * 2

    zeroCrossingKernel = getZeroCrossingKernel()

    row_size, col_size = np_img.shape
    targetImg = np.zeros((row_size - kernalPadding, col_size - kernalPadding), dtype = np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    laplacianMask = np.zeros((row_size - kernalPadding, col_size - kernalPadding), dtype = np.int64)
    
    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            gradientMagnitude = 0.0
            for k in kernel:
                gradientMagnitude += np_img[i + kernalShift + int(k[0])][j + kernalShift + int(k[1])] * k[2]
            if gradientMagnitude >= threshold * kernalScale:
                laplacianMask[i][j] = 1
            elif gradientMagnitude <= -threshold * kernalScale:
                laplacianMask[i][j] = -1
            else:
                laplacianMask[i][j] = 0

    for i in range(kernalShift):
        laplacianMask = padding(laplacianMask)

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            having_edge = False

            if laplacianMask[i + kernalShift][j + kernalShift] == 1:

                for k in zeroCrossingKernel:
                    if laplacianMask[i + kernalShift + int(k[0])][j + kernalShift + int(k[1])] == -1:
                        having_edge = True
                        break

            if not having_edge:
                targetImg[i][j] = 255
                
    return targetImg

def doLaplacian1(np_img, threshold = 15):

    kernel = np.array([
        [-1, -1, 0], [-1, 0,  1], [-1, 1, 0],
        [ 0, -1, 1], [ 0, 0, -4], [ 0, 1, 1],
        [ 1, -1, 0], [ 1, 0,  1], [ 1, 1, 0],
    ])

    return getLaplacianImg(np_img, threshold, kernel)

def doLaplacian2(np_img, threshold = 15):

    kernel = np.array([
        [-1, -1, 1], [-1, 0,  1], [-1, 1, 1],
        [ 0, -1, 1], [ 0, 0, -8], [ 0, 1, 1],
        [ 1, -1, 1], [ 1, 0,  1], [ 1, 1, 1],
    ])

    return getLaplacianImg(np_img, threshold, kernel, kernalScale = 3)

def doMinVarLaplacian(np_img, threshold = 20):
    kernel = np.array([
        [-1, -1,  2], [-1, 0, -1], [-1, 1,  2],
        [ 0, -1, -1], [ 0, 0, -4], [ 0, 1, -1],
        [ 1, -1,  2], [ 1, 0, -1], [ 1, 1,  2],
    ])

    return getLaplacianImg(np_img, threshold, kernel, kernalScale = 3)

def doLaplacianOfGaussian(np_img, threshold = 3000):
    kernel1 = [
        [-5, -5,  0], [-5, -4,  0], [-5, -3,  0], [-5, -2, -1], [-5, -1, -1],
        [-5,  5,  0], [-5,  4,  0], [-5,  3,  0], [-5,  2, -1], [-5,  1, -1],
        [-5,  0, -2],

        [-4, -5,  0], [-4, -4,  0], [-4, -3, -2], [-4, -2, -4], [-4, -1, -8],
        [-4,  5,  0], [-4,  4,  0], [-4,  3, -2], [-4,  2, -4], [-4,  1, -8],
        [-4,  0, -9],

        [-3, -5,  0], [-3, -4, -2], [-3, -3, -7], [-3, -2, -15], [-3, -1, -22],
        [-3,  5,  0], [-3,  4, -2], [-3,  3, -7], [-3,  2, -15], [-3,  1, -22],
        [-3,  0, -23],

        [-2, -5, -1], [-2, -4, -4], [-2, -3, -15], [-2, -2, -24], [-2, -1, -14],
        [-2,  5, -1], [-2,  4, -4], [-2,  3, -15], [-2,  2, -24], [-2,  1, -14],
        [-2,  0, -1],

        [-1, -5, -1], [-1, -4, -8], [-1, -3, -22], [-1, -2, -14], [-1, -1,  52],
        [-1,  5, -1], [-1,  4, -8], [-1,  3, -22], [-1,  2, -14], [-1,  1,  52],
        [-1,  0, 103],

        [ 0, -5, -2], [ 0, -4, -9], [ 0, -3, -23], [ 0, -2, -1], [ 0, -1,  103],
        [ 0,  5, -2], [ 0,  4, -9], [ 0,  3, -23], [ 0,  2, -1], [ 0,  1,  103],
        [ 0,  0, 178],
    ]

    kernel2 = []
    for k in kernel1:
        if k[0] < 0:
            kernel2.append([-k[0], k[1], k[2]])

    kernel = np.array(kernel1 + kernel2)

    return getLaplacianImg(np_img, threshold, kernel, kernalSize = 11)

def doDifferenceOfGaussian(np_img, threshold = 1):
    kernel1 = [
        [-5, -5, -1], [-5, -4, -3], [-5, -3, -4], [-5, -2, -6], [-5, -1, -7],
        [-5,  5, -1], [-5,  4, -3], [-5,  3, -4], [-5,  2, -6], [-5,  1, -7],
        [-5,  0, -8],

        [-4, -5, -3], [-4, -4, -5], [-4, -3, -8], [-4, -2, -11], [-4, -1, -13],
        [-4,  5, -3], [-4,  4, -5], [-4,  3, -8], [-4,  2, -11], [-4,  1, -13],
        [-4,  0, -13],

        [-3, -5, -4], [-3, -4, -8], [-3, -3, -12], [-3, -2, -16], [-3, -1, -17],
        [-3,  5, -4], [-3,  4, -8], [-3,  3, -12], [-3,  2, -16], [-3,  1, -17],
        [-3,  0, -17],

        [-2, -5, -6], [-2, -4, -11], [-2, -3, -16], [-2, -2, -16], [-2, -1,  0],
        [-2,  5, -6], [-2,  4, -11], [-2,  3, -16], [-2,  2, -16], [-2,  1,  0],
        [-2,  0, 15],

        [-1, -5, -7], [-1, -4, -13], [-1, -3, -17], [-1, -2,  0], [-1, -1,  85],
        [-1,  5, -7], [-1,  4, -13], [-1,  3, -17], [-1,  2,  0], [-1,  1,  85],
        [-1,  0, 160],

        [ 0, -5, -8], [ 0, -4, -13], [ 0, -3, -17], [ 0, -2, 15], [ 0, -1,  160],
        [ 0,  5, -8], [ 0,  4, -13], [ 0,  3, -17], [ 0,  2, 15], [ 0,  1,  160],
        [ 0,  0, 283],
    ]

    kernel2 = []
    for k in kernel1:
        if k[0] < 0:
            kernel2.append([-k[0], k[1], k[2]])

    kernel = np.array(kernel1 + kernel2)

    return getLaplacianImg(np_img, threshold, kernel, kernalSize = 11)




path = './results'
if not os.path.isdir(path):
    os.mkdir(path)

img = Image.open('lena.bmp')
np_img = np.array(img, dtype = np.int64)

np_img_1_time_padding = padding((np_img))

Laplacian1 = doLaplacian1(np_img_1_time_padding, threshold = 15)
Image.fromarray(np.uint8(Laplacian1)).save('results/LaplaceMask1.png')

Laplacian2 = doLaplacian2(np_img_1_time_padding, threshold = 15)
Image.fromarray(np.uint8(Laplacian2)).save('results/LaplaceMask2.png')

MinimumVarianceLaplace = doMinVarLaplacian(np_img_1_time_padding, threshold = 20)
Image.fromarray(np.uint8(MinimumVarianceLaplace)).save('results/MinimumVarianceLaplace.png')

np_img_5_times_padding = padding(padding(padding(padding(np_img_1_time_padding))))
LaplaceOfGaussian = doLaplacianOfGaussian(np_img_5_times_padding, threshold = 3000)
Image.fromarray(np.uint8(LaplaceOfGaussian)).save('results/LaplaceOfGaussian.png')

DifferenceOfGaussian = doDifferenceOfGaussian(np_img_5_times_padding, threshold = 1)
Image.fromarray(np.uint8(DifferenceOfGaussian)).save('results/DifferenceOfGaussian.png')
