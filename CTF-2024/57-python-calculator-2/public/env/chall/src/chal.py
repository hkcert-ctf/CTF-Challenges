import string

func_blacklist = [
    "__spec__",
    "__import__",
    "__loader__",
    "compile",
    "copyright",
    "credits",
    "eval",
    "exec",
    "help",
    "breakpoint",
    "license",
    "open",
    "input",
    "type",
    "vars",
    "delattr",
    "getattr",
    "setattr",
    "super",
    "object",
    "globals",
]


def _OK(inp):
    charset = string.ascii_letters + string.digits + "\"'+-*/^:.@ \r\n"
    for ch in inp:
        if not (ch in charset):
            return False
    for _func in func_blacklist:
        if _func in inp:
            return False
    return True


# get user input
print("input: ", end="")
user_input = ""
while True:
    line = input()
    if line == "":
        break
    user_input += line
    user_input += "\n"

# check seucre
if not (_OK(user_input)):
    print("You're hacking!!")
    exit(-1)

# setup sandbox
user_input = (
    """
for _func in func_blacklist:
    globals()['__builtins__'].__dict__.pop(_func)

'''------line_break--------'''
"""
    + user_input
)

# calc result
print("answer:", end="")
exec(user_input)
