import numpy as np
from PIL import Image

def h(b, c ,d, e):
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
    

img = Image.open('lena.bmp')
np_img = np.array(img)

row_size = np_img.shape[0]
col_size = np_img.shape[1]


for i in range(row_size):
    for j in range(col_size):
        np_img[i][j] = 255 if(np_img[i][j] >= 128) else 0


new_size = 64
new_np_img = np.zeros((new_size, new_size), np.int8)
step_row = row_size // new_size
step_col = col_size // new_size
for i in range(0, row_size, step_row):
    for j in range(0, col_size, step_col):
        new_i = i // step_row
        new_j = j // step_col
        new_np_img[new_i][new_j] = np_img[i][j]


Yokoi_array = np.zeros((new_size, new_size), np.int8)

# x7  x2  x6 
# x3  x0  x1
# x8  x4  x5
for i in range (new_size):
    for j in range (new_size):
        x0 = new_np_img[i][j]

        x1 = 0 if j == new_size - 1 else new_np_img[i][j + 1]
        x2 = 0 if i == 0 else new_np_img[i - 1][j]
        x3 = 0 if j == 0 else new_np_img[i][j - 1]
        x4 = 0 if i == new_size - 1 else new_np_img[i + 1][j]
        x5 = 0 if (i == new_size - 1 or j == new_size - 1) else new_np_img[i + 1][j + 1]
        x6 = 0 if (i == 0 or j == new_size - 1) else new_np_img[i - 1][j + 1]
        x7 = 0 if (i == 0 or j == 0) else new_np_img[i - 1][j - 1]
        x8 = 0 if (i == new_size - 1 or j == 0) else new_np_img[i + 1][j - 1]

        a = ''
        if x0 != 0:
            a += h(x0, x1, x6, x2) 
            a += h(x0, x2, x7, x3) 
            a += h(x0, x3, x8, x4) 
            a += h(x0, x4, x5, x1) 
            label = f(a)
        else:
            continue

        Yokoi_array[i][j] = label

f_out = open("result.txt", "w")
for i in range(new_size):
        line = ""
        for j in range(new_size):
            if(Yokoi_array[i][j]):
                line += str(Yokoi_array[i][j])
            else:
                line += ' '
        line += "\n"
        f_out.write(line)