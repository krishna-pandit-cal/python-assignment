# 52. Max of Consecutive Pairs

# Problem Statement:
# Given a number N followed by N elements for every 2 consecutive numbers print the maximum of the 2.


# Input Description:
# The input consists of an integer N, followed by N elements. N is an integer such that N <= 100000,
# implying an O(n) time complexity solution is expected.


# Output Description:
# The output is a space-separated sequence of the maximums of every two consecutive numbers from
# the input.


# Sample Input:
# 5
# 1 1 3 0 5


# Sample Output:
# 1 3 3 5



def maxOfConsecutive(nums):
    result = []
    for i in range(1, len(nums)):
        result.append(max(nums[i-1], nums[i]))
    return result

n = int(input())
nums = []
for _ in range(n):
    nums.append(int(input()))

output = maxOfConsecutive(nums)
print(" ".join(map(str, output)))
