import numpy as np
from PIL import Image

def h(b, c, d, e):
    ans = ''
    if b != c:
        ans = 's'
    elif b == c:
        if (b != d or b != e):
            ans = 'q'
        elif (b == d and b == e):
            ans = 'r'
    return ans

def f(input):
    if input == "rrrr":
        return 5
    else:
        label = 0
        for i in input:
            if i == 'q':
                label += 1
        return label

def Yokoi_Operator(np_img):

    row_size = np_img.shape[0]
    col_size = np_img.shape[1]
    Yokoi_array = np.zeros((row_size, col_size), np.int32)

    # x7  x2  x6 
    # x3  x0  x1
    # x8  x4  x5
    for i in range (row_size):
        for j in range (col_size):

            x0 = np_img[i][j]
            x1 = 0 if j == col_size - 1 else np_img[i][j + 1]
            x2 = 0 if i == 0 else np_img[i - 1][j]
            x3 = 0 if j == 0 else np_img[i][j - 1]
            x4 = 0 if i == row_size - 1 else np_img[i + 1][j]
            x5 = 0 if (i == row_size - 1 or j == col_size - 1) else np_img[i + 1][j + 1]
            x6 = 0 if (i == 0 or j == col_size - 1) else np_img[i - 1][j + 1]
            x7 = 0 if (i == 0 or j == 0) else np_img[i - 1][j - 1]
            x8 = 0 if (i == row_size - 1 or j == 0) else np_img[i + 1][j - 1]

            a = ''
            if x0 != 0:
                a += h(x0, x1, x6, x2) 
                a += h(x0, x2, x7, x3) 
                a += h(x0, x3, x8, x4) 
                a += h(x0, x4, x5, x1) 
                label = f(a)
            else:
                label = 7
            Yokoi_array[i][j] = label
    return Yokoi_array

def Pair_Operator(np_img):

    m = 1
    row_size = np_img.shape[0]
    col_size = np_img.shape[1]
    pair_list = list()
    h = (lambda a, m : 1 if a == m else 0)
    for i in range(row_size):
        for j in range(col_size):
            x0 = np_img[i][j]
            if x0 != 7 :
                x1 = 0 if j == col_size - 1 else np_img[i][j + 1]
                x2 = 0 if i == 0 else np_img[i - 1][j]
                x3 = 0 if j == 0 else np_img[i][j - 1]
                x4 = 0 if i == row_size - 1 else np_img[i + 1][j]

                sum_h = h(x1, m) + h(x2, m) + h(x3, m) + h(x4, m)
                pair_list.append('p' if (sum_h >= 1 and x0 == m) else 'q')
            else:
                pair_list.append('g')

    np_pair = np.array(pair_list).reshape((row_size, col_size))
    return np_pair

def Shrink_Operator(np_pair):

    row_size = np_pair.shape[0]
    col_size = np_pair.shape[1]
    output = np.zeros((row_size, col_size), np.int32)

    h = (lambda b, c, d, e : 1 if ( (c != 'g') and ( (d == 'g') or ( e == 'g' )) ) else 0)
    f = (lambda a1, a2, a3, a4, x : 'g' if ( a1+a2+a3+a4 ) == 1 else x)

    for i in range(row_size):
        for j in range(col_size):
            x0 = np_pair[i][j]
            if x0 == 'p':

                x1 = 'g' if j == col_size - 1 else np_pair[i][j + 1]
                x2 = 'g' if i == 0 else np_pair[i - 1][j]
                x3 = 'g' if j == 0 else np_pair[i][j - 1]
                x4 = 'g' if i == row_size - 1 else np_pair[i + 1][j]
                x5 = 'g' if (i == row_size - 1 or j == col_size - 1) else np_pair[i + 1][j + 1]
                x6 = 'g' if (i == 0 or j == col_size - 1) else np_pair[i - 1][j + 1]
                x7 = 'g' if (i == 0 or j == 0) else np_pair[i - 1][j - 1]
                x8 = 'g' if (i == row_size - 1 or j == 0) else np_pair[i + 1][j - 1]

                a1 = h(x0, x1, x6, x2)
                a2 = h(x0, x2, x7, x3)
                a3 = h(x0, x3, x8, x4)
                a4 = h(x0, x4, x5, x1)

                np_pair[i][j] = f(a1, a2, a3, a4, x0)

    for i in range(row_size):
        for j in range(col_size):
            if np_pair[i][j] != 'g':
                output[i][j] = 255
    return output





img = Image.open('lena.bmp')
np_img = np.array(img)

row_size = np_img.shape[0]
col_size = np_img.shape[1]


for i in range(row_size):
    for j in range(col_size):
        np_img[i][j] = 255 if(np_img[i][j] >= 128) else 0



new_size = 64
new_np_img = np.zeros((new_size, new_size), np.uint)
step_row = row_size // new_size
step_col = col_size // new_size
for i in range(0, row_size, step_row):
    for j in range(0, col_size, step_col):
        new_i = i // step_row
        new_j = j // step_col
        new_np_img[new_i][new_j] = np_img[i][j]


np_thin = np.copy(new_np_img)
thin_row_size = np_thin.shape[0]
thin_col_size = np_thin.shape[0]

iter = 1
Flag = True
while Flag:

    print("iter: ", iter)
    np_original = np.copy(np_thin)
    Flag = False


    np_yokoi = Yokoi_Operator(np_thin)
    np_pair = Pair_Operator(np_yokoi)
    np_thin = Shrink_Operator(np_pair)


    output = Image.fromarray(np.uint8(np_thin))
    output.save('result{}.png'.format(iter))


    for i in range(thin_row_size):
        for j in range(thin_col_size):
            if np_original[i][j] != np_thin[i][j]:
                Flag = True
                break
    iter += 1