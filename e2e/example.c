#include <stdio.h>
#include <stdlib.h>

// Function with complex multi-level loops
int complex_loops(int n, int *arr) {
    int sum = 0;
    int i, j, k;
    
    // Outer loop
    for (i = 0; i < n; i++) {
        // First nested loop
        for (j = 0; j < n - i; j++) {
            // Second nested loop
            for (k = 0; k < j + 1; k++) {
                if (arr != NULL && i + j + k < n) {
                    sum += arr[i * n + j];
                }
            }
            // Inner while loop within nested for loops
            int temp = j;
            while (temp > 0) {
                sum += temp;
                temp /= 2;
            }
        }
        
        // Another nested loop with different structure
        for (j = i; j < n; j++) {
            int count = 0;
            do {
                if (count % 2 == 0) {
                    sum += i * j;
                } else {
                    sum -= count;
                }
                count++;
            } while (count < 5);
        }
    }
    
    return sum;
}

// Function with complex if-else but no loops
int complex_conditionals(int a, int b, int c, int d, int *result) {
    int value = 0;
    
    if (a > 0) {
        if (b < 10) {
            if (c == 5) {
                value = a + b + c;
            } else if (c > 5) {
                if (d != 0) {
                    value = (a * b) / d;
                } else {
                    value = a * b;
                }
            } else {
                if (c > 0) {
                    value = a - b + c;
                } else {
                    value = a - b;
                }
            }
        } else {
            if (b < 20) {
                if (c > d) {
                    value = a + c - d;
                } else if (c < d) {
                    value = a + d - c;
                } else {
                    value = a;
                }
            } else {
                value = a * 2;
            }
        }
    } else {
        if (a == 0) {
            if (b > 0) {
                if (c > 0 && d > 0) {
                    value = b * c * d;
                } else if (c > 0 || d > 0) {
                    value = b + c + d;
                } else {
                    value = b;
                }
            } else {
                if (b < 0) {
                    value = c - d;
                } else {
                    value = c + d;
                }
            }
        } else {
            if (abs(a) > abs(b)) {
                value = a + b;
            } else {
                if (abs(b) > abs(c)) {
                    if (abs(c) > abs(d)) {
                        value = a - b - c - d;
                    } else {
                        value = a - b - c;
                    }
                } else {
                    value = a - b;
                }
            }
        }
    }
    
    if (result != NULL) {
        if (value > 100) {
            *result = value % 100;
        } else if (value < -100) {
            *result = value % -100;
        } else {
            *result = value;
        }
    }
    
    return value;
}

int main() {
    int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int result;
    
    int sum1 = complex_loops(5, arr);
    int sum2 = complex_conditionals(10, 5, 5, 2, &result);
    
    printf("Complex loops result: %d\n", sum1);
    printf("Complex conditionals result: %d\n", sum2);
    
    return 0;
}

