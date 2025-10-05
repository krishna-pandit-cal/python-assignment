# 302. Three Prime Sum Representation

# Problem Statement:
# Given a number N, print its representation as sum of three primes(print the numbers in increasing order).
# If more than one answer exists print the answer where the first and second number is smallest.


# Input Description:
# The input consists of a number N, where 6 <= N <= 100000.


# Sample Input:
# 12


# Sample Output:
# 2 3 7


# Solution:

# Generate all primes up to 𝑁using Sieve of Eratosthenes (efficient).
def sieve(n):
    is_prime = [True] * (n + 1)
    is_prime[0] = is_prime[1] = False

    for i in range(2, int(n**0.5) + 1):
        if is_prime[i]:
            for j in range(i * i, n + 1, i):
                is_prime[j] = False

    primes = [i for i in range(n + 1) if is_prime[i]]
    return primes, is_prime

def sum_of_three(n):
    primes, is_prime = sieve(n)
    l = len(primes)

    for i in range(l):
        for j in range(i, l):
           first, second = primes[i], primes[j]
           third = n - (first + second)

           if is_prime[third] and third >= second and third <= n:
               return (first, second, third)
    return None

n = int(input())
result = sum_of_three(n)
print(" ".join(map(str, result)))
