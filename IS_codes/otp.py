
import random

def generate_otp():
    # Generate an 8-digit OTP
    otp = random.randint(10000000, 99999999)  # Random number between 10 million(smallest 8 digit) and 99 million(Highest 8 digit)
    return otp


for i in range(0,5,1):
    otp = generate_otp()
    print(f"{i+1}. Your 8-digit OTP is: {otp}")
