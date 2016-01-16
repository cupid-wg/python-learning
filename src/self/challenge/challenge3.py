# http://www.pythonchallenge.com/pc/def/ocr.html
# first count out the chars
from copy import deepcopy
f = open('challenge3.txt', 'r')
a = {}
for line in f:
    for char in line:
        if char != '' and char != '\n':
            if a.get(char) is not None:
                a[char] += 1
            else:
                a[char] = 1

chars = []
for k, v in a.items():
    if v == 1:
        chars.append(k)

print(chars)

# arrange the chars


def arrange_list(list):
    if len(list) == 2:
        return[[list[0], list[1]], [list[1], list[0]]]
    else:
        return_list = []
        max_len = len(list)
        for i in range(0, max_len):
            tmp_list = deepcopy(list)
            tmp_head = tmp_list[i]
            del tmp_list[i]
            tmp_return = arrange_list(tmp_list)
            for item in tmp_return:
                tmp = [tmp_head]
                tmp.extend(item)
                return_list.append(tmp)
        return return_list

list = arrange_list(chars)
for item in list:
    print(''.join(item))
