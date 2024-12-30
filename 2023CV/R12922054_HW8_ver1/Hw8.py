import numpy as np
from PIL import Image
import math
import random
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


def generateGaussianNoise(np_img, amplitude):
    targetImg = np.copy(np_img)
    
    row_size, col_size = np_img.shape
    for i in range(row_size):
        for j in range(col_size):
            noiseValue = np_img[i][j] + amplitude * random.gauss(0, 1)
            noiseValue = 255 if noiseValue > 255 else noiseValue
            targetImg[i][j] = noiseValue

    return targetImg

def generateSaltAndPepperNoise(np_img, threshold):
    targetImg = np.copy(np_img)

    row_size, col_size = np_img.shape
    for i in range(row_size):
        for j in range(col_size):
            randomValue = random.uniform(0, 1)
            if (randomValue <= threshold):   
                targetImg[i][j] = 0
            elif (randomValue >= (1-threshold)):
                targetImg[i][j] = 255

    return targetImg

def dilation(np_img, kernel):
    row_size, col_size = np_img.shape

    dilation_img =  np.zeros((row_size, col_size), dtype = np.int64)
    
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

def erosion(np_img, kernel):
    row_size, col_size = np_img.shape

    erosion_img = np.zeros((row_size, col_size), dtype = np.int64)

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

def opening(np_img, kernel):
    return dilation(erosion(np_img, kernel), kernel)

def closing(np_img, kernel):
    return erosion(dilation(np_img, kernel), kernel)

def boxFilter(np_img, filterSize = 3):
    row_size, col_size = np_img.shape

    tmpImg = np.zeros((row_size, col_size), dtype=np.int64)
    pitch = filterSize // 2
    kernel = []
    for i in range(-pitch, pitch + 1):
        for j in range(-pitch, pitch + 1):
            kernel.append((i, j))

    kernel_size = len(kernel)
    for i in range(pitch, row_size - pitch):
        for j in range(pitch, col_size - pitch):
            for k in kernel:
                rowShift, colShift = k
                tmpImg[i][j] += np_img[i + rowShift][j + colShift]
            tmpImg[i][j] = tmpImg[i][j] / kernel_size

    targetImg = np.zeros((row_size - 2*pitch, col_size - 2*pitch), dtype=np.int64)
    targetImgRow_size, targetImgCol_size = targetImg.shape
    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            targetImg[i][j] = tmpImg[i + pitch][j + pitch]

    return targetImg

def medianFilter(np_img, filterSize = 3):
    row_size, col_size = np_img.shape

    tmpImg = np.zeros((row_size, col_size), dtype=np.int64)

    pitch = filterSize // 2
    kernel = []
    for i in range(-pitch, pitch + 1):
        for j in range(-pitch, pitch + 1):
            kernel.append((i, j))

    for i in range(pitch, row_size - pitch):
        for j in range(pitch, col_size - pitch):
            tmp = list()
            for k in kernel:
                rowShift, colShift = k
                tmp.append(np_img[i + rowShift][j + colShift])
            tmpImg[i][j] = np.median(tmp)
            
    targetImg = np.zeros((row_size - 2*pitch, col_size - 2*pitch), dtype=int)
    targetImgRow_size, targetImgCol_size = targetImg.shape

    for i in range(targetImgRow_size):
        for j in range(targetImgCol_size):
            targetImg[i][j] = tmpImg[i + pitch][j + pitch]

    return targetImg

def BoxFilter_3x3and5x5(np_img, 
                        gaussianAmpli_10_pad1Step, gaussianAmpli_10_pad2Step,
                        gaussianAmpli_30_pad1Step, gaussianAmpli_30_pad2Step,
                        saltandpepperProb5_pad1Step, saltandpepperProb5_pad2Step,
                        saltandpepperProb10_pad1Step, saltandpepperProb10_pad2Step):

    gaussianAmpli_10_withBoxFilter3x3 = boxFilter(gaussianAmpli_10_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(gaussianAmpli_10_withBoxFilter3x3)).save('./results/gaussianAmpli_10_withBoxFilter3x3.png')
    print("[SNR] Gaussian noise with amplitude 10 do boxFilter 3x3 : ", caculateSNR(gaussianAmpli_10_withBoxFilter3x3, np_img))

    gaussianAmpli_10_withBoxFilter5x5 = boxFilter(gaussianAmpli_10_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(gaussianAmpli_10_withBoxFilter5x5)).save('./results/gaussianAmpli_10_withBoxFilter5x5.png')
    print("[SNR] Gaussian noise with amplitude 10 do boxFilter 5x5 : ", caculateSNR(gaussianAmpli_10_withBoxFilter5x5, np_img))

    gaussianAmpli_30_withBoxFilter3x3 = boxFilter(gaussianAmpli_30_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(gaussianAmpli_30_withBoxFilter3x3)).save('./results/gaussianAmpli_30_withBoxFilter3x3.png')
    print("[SNR] Gaussian noise with amplitude 30 do boxFilter 3x3 : ", caculateSNR(gaussianAmpli_30_withBoxFilter3x3, np_img))

    gaussianAmpli_30_withBoxFilter5x5 = boxFilter(gaussianAmpli_30_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(gaussianAmpli_30_withBoxFilter5x5)).save('./results/gaussianAmpli_30_withBoxFilter5x5.png')
    print("[SNR] Gaussian noise with amplitude 30 do boxFilter 5x5 : ", caculateSNR(gaussianAmpli_30_withBoxFilter5x5, np_img))




    saltandpepperProb5_withBoxFilter3x3 = boxFilter(saltandpepperProb5_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(saltandpepperProb5_withBoxFilter3x3)).save('./results/saltandpepperProb5_withBoxFilter3x3.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do boxFilter 3x3 : ", caculateSNR(saltandpepperProb5_withBoxFilter3x3, np_img))

    saltandpepperProb5_withBoxFilter5x5 = boxFilter(saltandpepperProb5_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(saltandpepperProb5_withBoxFilter5x5)).save('./results/saltandpepperProb5_withBoxFilter5x5.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do boxFilter 5x5 : ", caculateSNR(saltandpepperProb5_withBoxFilter5x5, np_img))

    saltandpepperProb10_withBoxFilter3x3 = boxFilter(saltandpepperProb10_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(saltandpepperProb10_withBoxFilter3x3)).save('./results/saltandpepperProb10_withBoxFilter3x3.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do boxFilter 3x3 : ", caculateSNR(saltandpepperProb10_withBoxFilter3x3, np_img))

    saltandpepperProb10_withBoxFilter5x5 = boxFilter(saltandpepperProb10_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(saltandpepperProb10_withBoxFilter5x5)).save('./results/saltandpepperProb10_withBoxFilter5x5.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do boxFilter 5x5 : ", caculateSNR(saltandpepperProb10_withBoxFilter5x5, np_img))

def MedianFilter_3x3and5x5(np_img, 
                        gaussianAmpli_10_pad1Step, gaussianAmpli_10_pad2Step,
                        gaussianAmpli_30_pad1Step, gaussianAmpli_30_pad2Step,
                        saltandpepperProb5_pad1Step, saltandpepperProb5_pad2Step,
                        saltandpepperProb10_pad1Step, saltandpepperProb10_pad2Step):
    # gaussian
    gaussianAmpli_10_withMedianFilter3x3 = medianFilter(gaussianAmpli_10_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(gaussianAmpli_10_withMedianFilter3x3)).save('./results/gaussianAmpli_10_withMedianFilter3x3.png')
    print("[SNR] Gaussian noise with amplitude 10 do medianFilter 3x3 : ", caculateSNR(gaussianAmpli_10_withMedianFilter3x3, np_img))

    gaussianAmpli_10_withMedianFilter5x5 = medianFilter(gaussianAmpli_10_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(gaussianAmpli_10_withMedianFilter5x5)).save('./results/gaussianAmpli_10_withMedianFilter5x5.png')
    print("[SNR] Gaussian noise with amplitude 10 do medianFilter 5x5 : ", caculateSNR(gaussianAmpli_10_withMedianFilter5x5, np_img))

    gaussianAmpli_30_withMedianFilter3x3 = medianFilter(gaussianAmpli_30_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(gaussianAmpli_30_withMedianFilter3x3)).save('./results/gaussianAmpli_30_withMedianFilter3x3.png')
    print("[SNR] Gaussian noise with amplitude 30 do medianFilter 3x3 : ", caculateSNR(gaussianAmpli_30_withMedianFilter3x3, np_img))

    gaussianAmpli_30_withMedianFilter5x5 = medianFilter(gaussianAmpli_30_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(gaussianAmpli_30_withMedianFilter5x5)).save('./results/gaussianAmpli_30_withMedianFilter5x5.png')
    print("[SNR] Gaussian noise with amplitude 30 do medianFilter 5x5 : ", caculateSNR(gaussianAmpli_30_withMedianFilter5x5, np_img))




    saltandpepperProb5_withMedianFilter3x3 = medianFilter(saltandpepperProb5_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(saltandpepperProb5_withMedianFilter3x3)).save('./results/saltandpepperProb5_withMedianFilter3x3.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do medianFilter 3x3 : ", caculateSNR(saltandpepperProb5_withMedianFilter3x3, np_img))

    saltandpepperProb5_withMedianFilter5x5 = medianFilter(saltandpepperProb5_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(saltandpepperProb5_withMedianFilter5x5)).save('./results/saltandpepperProb5_withMedianFilter5x5.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do medianFilter 5x5 : ", caculateSNR(saltandpepperProb5_withMedianFilter5x5, np_img))

    saltandpepperProb10_withMedianFilter3x3 = medianFilter(saltandpepperProb10_pad1Step, filterSize = 3)
    Image.fromarray(np.uint8(saltandpepperProb10_withMedianFilter3x3)).save('./results/saltandpepperProb10_withMedianFilter3x3.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do medianFilter 3x3 : ", caculateSNR(saltandpepperProb10_withMedianFilter3x3, np_img))

    saltandpepperProb10_withMedianFilter5x5 = medianFilter(saltandpepperProb10_pad2Step, filterSize = 5)
    Image.fromarray(np.uint8(saltandpepperProb10_withMedianFilter5x5)).save('./results/saltandpepperProb10_withMedianFilter5x5.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do medianFilter 5x5 : ", caculateSNR(saltandpepperProb10_withMedianFilter5x5, np_img))

def OpCl_And_ClOpFilter(np_img,
                    gaussianAmpli_10, gaussianAmpli_30, 
                    saltandpepperProb5, saltandpepperProb10):
    kernel = np.array(
        [
            [-2, -1,  0], [-2,  0,  0], [-2,  1,  0],
            [-1, -2,  0], [-1, -1,  0], [-1,  0,  0], [-1,  1,  0], [-1,  2,  0],
            [ 0, -2,  0], [ 0, -1,  0], [ 0,  0,  0], [ 0,  1,  0], [ 0,  2,  0],
            [ 1, -2,  0], [ 1, -1,  0], [ 1,  0,  0], [ 1,  1,  0], [ 1,  2,  0],
            [ 2, -1,  0], [ 2,  0,  0], [ 2,  1,  0]
        ]
    )
    # gaussian
    gaussianAmpli_10_withOpening_Closing = closing(opening(gaussianAmpli_10, kernel), kernel)
    Image.fromarray(np.uint8(gaussianAmpli_10_withOpening_Closing)).save('./results/gaussianAmpli_10_withOpening_Closing.png')
    print("[SNR] Gaussian noise with amplitude 10 do Opening and Closing : ", caculateSNR(gaussianAmpli_10_withOpening_Closing, np_img))

    gaussianAmpli_10_withClosing_Opening = opening(closing(gaussianAmpli_10, kernel), kernel)
    Image.fromarray(np.uint8(gaussianAmpli_10_withClosing_Opening)).save('./results/gaussianAmpli_10_withClosing_Opening.png')
    print("[SNR] Gaussian noise with amplitude 10 do Closing and Opening : ", caculateSNR(gaussianAmpli_10_withClosing_Opening, np_img))

    gaussianAmpli_30_withOpening_Closing = closing(opening(gaussianAmpli_30, kernel), kernel)
    Image.fromarray(np.uint8(gaussianAmpli_30_withOpening_Closing)).save('./results/gaussianAmpli_30_withOpening_Closing.png')
    print("[SNR] Gaussian noise with amplitude 30 do Opening and Closing : ", caculateSNR(gaussianAmpli_30_withOpening_Closing, np_img))

    gaussianAmpli_30_withClosing_Opening = opening(closing(gaussianAmpli_30, kernel), kernel)
    Image.fromarray(np.uint8(gaussianAmpli_30_withClosing_Opening)).save('./results/gaussianAmpli_30_withClosing_Opening.png')
    print("[SNR] Gaussian noise with amplitude 30 do Closing and Opening : ", caculateSNR(gaussianAmpli_30_withClosing_Opening, np_img))

    # salt and pepper
    saltandpepperProb5_withOpening_Closing = closing(opening(saltandpepperProb5, kernel), kernel)
    Image.fromarray(np.uint8(saltandpepperProb5_withOpening_Closing)).save('./results/saltandpepperProb5_withOpening_Closing.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do Opening and Closing : ", caculateSNR(saltandpepperProb5_withOpening_Closing, np_img))

    saltandpepperProb5_withClosing_Opening = opening(closing(saltandpepperProb5, kernel), kernel)
    Image.fromarray(np.uint8(saltandpepperProb5_withClosing_Opening)).save('./results/saltandpepperProb5_withClosing_Opening.png')
    print("[SNR] Salt and Pepper noise with Prob 0.05 do Closing and Opening : ", caculateSNR(saltandpepperProb5_withClosing_Opening, np_img))
   
    saltandpepperProb10_withOpening_Closing = closing(opening(saltandpepperProb10, kernel), kernel)
    Image.fromarray(np.uint8(saltandpepperProb10_withOpening_Closing)).save('./results/saltandpepperProb10_withOpening_Closing.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do Opening and Closing : ", caculateSNR(saltandpepperProb10_withOpening_Closing, np_img))

    saltandpepperProb10_withClosing_Opening = opening(closing(saltandpepperProb10, kernel), kernel)
    Image.fromarray(np.uint8(saltandpepperProb10_withClosing_Opening)).save('./results/saltandpepperProb10_withClosing_Opening.png')
    print("[SNR] Salt and Pepper noise with Prob 0.10 do Closing and Opening : ", caculateSNR(saltandpepperProb10_withClosing_Opening, np_img))

def caculateSNR(noiseNpImg, oriNpImg):
    row_size, col_size = noiseNpImg.shape

    newNoiseNpImg = np.copy(noiseNpImg).astype(np.float64)
    newOriNpImg = np.copy(oriNpImg).astype(np.float64)
    
    for i in range(row_size):
        for j in range(col_size):
            newOriNpImg[i][j] = newOriNpImg[i][j] / 255
            newNoiseNpImg[i][j] = newNoiseNpImg[i][j] / 255

    muSignal = 0
    muNoise = 0
    for i in range(row_size):
        for j in range(col_size):
            muSignal += newOriNpImg[i][j]
            muNoise += newNoiseNpImg[i][j] - newOriNpImg[i][j]
    muSignal = muSignal / (row_size * col_size)
    muNoise = muNoise / (row_size * col_size)

    varianceSignal = 0
    varianceNoise = 0
    for i in range(row_size):
        for j in range(col_size):
            varianceSignal += (newOriNpImg[i][j] - muSignal) ** 2
            varianceNoise += (newNoiseNpImg[i][j] - newOriNpImg[i][j] - muNoise) ** 2
    varianceSignal = varianceSignal / (row_size * col_size)
    varianceNoise = varianceNoise / (row_size * col_size)

    SNR_value = 20 * math.log(math.sqrt(varianceSignal / varianceNoise), 10)

    return SNR_value




path = './results'
if not os.path.isdir(path):
    os.mkdir(path)
    
img = Image.open('lena.bmp')
np_img = np.array(img, dtype=np.int64)

gaussianAmpli_10 = generateGaussianNoise(np_img, 10)
Image.fromarray(np.uint8(gaussianAmpli_10)).save('./results/gaussianAmpli_10.png')
print("[SNR] Gaussian noise with amplitude 10 : ", caculateSNR(gaussianAmpli_10, np_img))

gaussianAmpli_30 = generateGaussianNoise(np_img, 30)
Image.fromarray(np.uint8(gaussianAmpli_30)).save('./results/gaussianAmpli_30.png')
print("[SNR] Gaussian noise with amplitude 30 : ", caculateSNR(gaussianAmpli_30, np_img))



saltandpepperProb5 = generateSaltAndPepperNoise(np_img, 0.05)
Image.fromarray(np.uint8(saltandpepperProb5)).save('./results/saltandpepperProb5.png')
print("[SNR] Salt and Pepper noise with probability 0.05 : ", caculateSNR(saltandpepperProb5, np_img))



saltandpepperProb10 = generateSaltAndPepperNoise(np_img, 0.10)
Image.fromarray(np.uint8(saltandpepperProb10)).save('./results/saltandpepperProb10.png')
print("[SNR] Salt and Pepper noise with probability 0.1 : ", caculateSNR(saltandpepperProb10, np_img))



gaussianAmpli_10_pad1Step = padding(gaussianAmpli_10)
gaussianAmpli_10_pad2Step = padding(gaussianAmpli_10_pad1Step)

gaussianAmpli_30_pad1Step = padding(gaussianAmpli_30)
gaussianAmpli_30_pad2Step = padding(gaussianAmpli_30_pad1Step)

saltandpepperProb5_pad1Step = padding(saltandpepperProb5)
saltandpepperProb5_pad2Step = padding(saltandpepperProb5_pad1Step)

saltandpepperProb10_pad1Step = padding(saltandpepperProb10)
saltandpepperProb10_pad2Step = padding(saltandpepperProb10_pad1Step)


BoxFilter_3x3and5x5(np_img, 
                    gaussianAmpli_10_pad1Step, gaussianAmpli_10_pad2Step,
                    gaussianAmpli_30_pad1Step, gaussianAmpli_30_pad2Step,
                    saltandpepperProb5_pad1Step, saltandpepperProb5_pad2Step,
                    saltandpepperProb10_pad1Step, saltandpepperProb10_pad2Step)

MedianFilter_3x3and5x5(np_img,
                    gaussianAmpli_10_pad1Step, gaussianAmpli_10_pad2Step,
                    gaussianAmpli_30_pad1Step, gaussianAmpli_30_pad2Step,
                    saltandpepperProb5_pad1Step, saltandpepperProb5_pad2Step,
                    saltandpepperProb10_pad1Step, saltandpepperProb10_pad2Step)

OpCl_And_ClOpFilter(np_img,
                    gaussianAmpli_10, gaussianAmpli_30, 
                    saltandpepperProb5, saltandpepperProb10)

