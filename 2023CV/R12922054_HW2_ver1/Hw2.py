import numpy as np
import cv2
import copy
from PIL import Image
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def GeneratingBinaryImg(img, r_size, c_size, threshhold):
    copy_img = copy.deepcopy(img)
    for i in range (r_size):
        for j in range (c_size):
            copy_img[i][j] = 255 if(copy_img[i][j] >= threshhold) else 0
    
    result = Image.fromarray(copy_img)
    return result

def GeneratingHistogram(img, r_size, c_size):
    copy_img = copy.deepcopy(img)
    
    dict_His = dict()
    list_His = list()
    
    for i in range (r_size):
        for j in range (c_size):
            if(copy_img[i][j] not in dict_His):
                dict_His[copy_img[i][j]] = 1
            else:
                dict_His[copy_img[i][j]] += 1
            list_His.append(copy_img[i][j])

    plt.hist(list_His, bins=256)
    plt.savefig("result-histogram_graph-1.png")  

    # list_His = list()
    # index = list()
    # for i in range (256):
    #     if(i in dict_His):
    #         list_His.append(dict_His[i])
    #     else :
    #         list_His.append(0)
    #     index.append(i)
        
    # plt.plot(index, list_His)
    # plt.savefig("result-histogram_graph-2.png")

    return

def GeneratingConnectedComponents(img, r_size, c_size):
    copy_img = copy.deepcopy(img)
    #1. Binarize
    for i in range (r_size):
        for j in range(c_size):
            copy_img[i][j] = 255 if (copy_img[i][j]) >= 128 else 0

    #2. Set unique numbers
    unique_number = 1
    unique_number_2Darray = np.zeros((r_size, c_size), dtype=int)
    for i in range (r_size):
        for j in range(c_size):
            if copy_img[i][j]:
                unique_number_2Darray[i][j] = unique_number
                unique_number += 1
            else:
                unique_number_2Darray[i][j] = 0

    # print(f'Unique Number = {unique_number}')

    # for i in range(r_size):
    #     for j in range(c_size):
    #         print(f'{unique_number_2Darray[i][j]} ',end = '')
    #     print()
    
    #3.Run iteration
    change_flag = False
    first_enter = True
    while change_flag or first_enter:
        change_flag = False
        if first_enter:
            first_enter = False
        for i in range (r_size):
            for j in range (c_size):
                if unique_number_2Darray[i][j]:
                    min_num = unique_number_2Darray[i][j]
                    if i-1 > 0:
                        if unique_number_2Darray[i-1][j] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i-1][j]) 
                    if j-1 > 0:
                        if unique_number_2Darray[i][j-1] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i][j-1]) 
                    if i+1 < r_size:
                        if unique_number_2Darray[i+1][j] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i+1][j]) 
                    if j+1 < c_size:
                        if unique_number_2Darray[i][j+1] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i][j+1]) 
                    if unique_number_2Darray[i][j] > min_num:
                        unique_number_2Darray[i][j] = min_num
                        change_flag = True

        for i in range (r_size-1, -1, -1):
            for j in range (c_size-1, -1, -1):
                if unique_number_2Darray[i][j]:
                    min_num = unique_number_2Darray[i][j]
                    if i-1 > 0:
                        if unique_number_2Darray[i-1][j] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i-1][j]) 
                    if j-1 > 0:
                        if unique_number_2Darray[i][j-1] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i][j-1]) 
                    if i+1 < r_size:
                        if unique_number_2Darray[i+1][j] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i+1][j]) 
                    if j+1 < c_size:
                        if unique_number_2Darray[i][j+1] != 0:
                            min_num = min(min_num, unique_number_2Darray[i][j], unique_number_2Darray[i][j+1]) 
                    if unique_number_2Darray[i][j] > min_num:
                        unique_number_2Darray[i][j] = min_num
                        change_flag = True
                   
    # for i in range(r_size):
    #     for j in range(c_size):
    #         print(f'{unique_number_2Darray[i][j]} ',end = '')
    #     print()

    #4. Prepare Ploting
    # Count the number of the number of unique_number_2Darray
    count_dict = dict()
    for i in range(r_size):
        for j in range(c_size):
            if unique_number_2Darray[i][j]: 
                if unique_number_2Darray[i][j] not in count_dict.keys():
                    count_dict[unique_number_2Darray[i][j]] = 1
                else:
                    count_dict[unique_number_2Darray[i][j]] += 1
    # print(f'Count_Dict = {count_dict}')

    height_dict = dict()
    width_dict  = dict()
    area500_uniq_num_list = list()
    for key, value in count_dict.items():
        if value > 500:
            area500_uniq_num_list.append(key)
            height_dict[key] = list()
            width_dict[key]  = list()

    print(f'Area500_uniq_num_list = {area500_uniq_num_list}')

    for index, uniq_num in enumerate(area500_uniq_num_list):
        for i in range(r_size):
            for j in range(c_size):
                if(unique_number_2Darray[i][j] == uniq_num):
                    height_dict[uniq_num].append(i)
                    width_dict[uniq_num].append(j)


    _, ax = plt.subplots()
    result_img = Image.fromarray(copy_img)
    ax.imshow(result_img, cmap=plt.cm.gray, vmin=0, vmax=255)

    for index, uniq_num in enumerate(area500_uniq_num_list):
        max_h  = max(height_dict[uniq_num])
        min_h  = min(height_dict[uniq_num])
        max_w  = max(width_dict[uniq_num])
        min_w  = min(width_dict[uniq_num])
        mean_h = int(sum(height_dict[uniq_num])/len(height_dict[uniq_num]))
        mean_w = int(sum(width_dict[uniq_num])/len(height_dict[uniq_num]))

        # create a Rectangle patch
        rect = patches.Rectangle((min_w, min_h), max_w-min_w, max_h-min_h, linewidth=1, edgecolor='b', facecolor='none')
        ax.add_patch(rect)
        plt.plot(mean_w, mean_h, marker='*', mew=4, ms=8, color='r')

        # copy_img = cv2.rectangle(copy_img, (min_w, min_h), (max_w, max_h), (255, 0, 0) , 2)

    plt.savefig('result-connected_components.png')

    # cv2.imwrite("result-connected_components.png", copy_img)



                        

    return


original_img = Image.open("lena.bmp")
numpy_original_img = np.array(original_img)

row_size = numpy_original_img.shape[0]
col_size = numpy_original_img.shape[1]

threshhold = 128
binary_img = GeneratingBinaryImg(numpy_original_img, row_size, col_size, threshhold)
binary_img.save("result-binary_img.png")

histogram_graph = GeneratingHistogram(numpy_original_img, row_size, col_size)

GeneratingConnectedComponents(numpy_original_img, row_size, col_size)