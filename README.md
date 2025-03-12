# **Password Generator Using Python**

```yaml
import random
import string

def generate_password(min_length, numbers=True, special_characters=True):
    letters = string.ascii_letters
    digits = string.digits
    special = string.punctuation

    print(letters, digits, special)

generate_password(10)    
```

![image.png](attachment:621a1bb4-21a5-4626-a995-784ba86b20eb:image.png)

So we need to combine all of these to one strong password