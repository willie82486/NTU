import copy
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image

def a_Img_and_Histogram(img, row_size, col_size):
    copy_img = copy.deepcopy(img)
    hist_list = list()

    for i in range(row_size):
        for j in range(col_size):
            hist_list.append(copy_img[i][j])

    img_a = Image.fromarray(copy_img)
    img_a.save("image_a.png")
    plt.clf()
    plt.hist(hist_list, bins=256)
    plt.savefig('histogram_a.png')
    return

def b_Img_and_Histogram(img, row_size, col_size):
    copy_img = copy.deepcopy(img)
    copy_img.astype(int)
    hist_list = list()

    for i in range(row_size):
        for j in range(col_size):
            copy_img[i][j] = copy_img[i][j] / 3
            hist_list.append(copy_img[i][j])

    img_b = Image.fromarray(copy_img)
    img_b.save("image_b.png")
    plt.clf()
    # plt.hist(hist_list, bins=256)
    plt.hist(hist_list, bins=256, range=[0, 255])
    plt.savefig('histogram_b.png')
    return copy_img


def c_Img_and_Histogram(img, row_size, col_size):
    copy_img = copy.deepcopy(img)
    copy_img.astype(int)
    record_list = np.zeros(256, dtype=int)
    prob_list = np.zeros(256, dtype=float)
    total_pixel = row_size * col_size
    max_luminance = 255

    for i in range(row_size):
        for j in range(col_size):
            record_list[copy_img[i][j]] = record_list[copy_img[i][j]] + 1

    for i in range(record_list.shape[0]):
        prob_list[i] = record_list[i]/(total_pixel)

    # get CDF
    prefix_sum = 0
    cdf_list = np.zeros(256, dtype=float)
    for i in range(prob_list.shape[0]):
        prefix_sum += prob_list[i]
        cdf_list[i] = prefix_sum

    for i in range(row_size):
        for j in range(col_size):
            copy_img[i][j] = cdf_list[copy_img[i][j]] * max_luminance

    img_c = Image.fromarray(copy_img)
    img_c.save("image_c.png")


    hist_list_c = list()
    for i in range(row_size):
        for j in range(col_size):
            hist_list_c.append(copy_img[i][j])

    plt.clf()
    plt.hist(hist_list_c, bins=256, range=[0, 255])
    plt.savefig('histogram_c.png')
    
    return

original_img = Image.open('lena.bmp')
numpy_original_img = np.array(original_img)

# print("HW3: ", numpy_original_img.shape)
row_size = numpy_original_img.shape[0]
col_size = numpy_original_img.shape[1]
a_Img_and_Histogram(numpy_original_img, row_size, col_size)
b_img = b_Img_and_Histogram(numpy_original_img, row_size, col_size)
c_Img_and_Histogram(b_img, row_size, col_size)