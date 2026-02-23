Load the model with PyTorch, convert characters from 32 to 127 into tensors as input to the model to view the results, which will reveal the correspondence between plaintext and ciphertext. Then, perform reverse substitution on the ciphertext of the flag.
```python
import torch
import torch.nn as nn

class MyNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear1 = nn.Linear(1, 512)
        self.linear2 = nn.Linear(512, 2048)
        self.linear3 = nn.Linear(2048, 1024)
        self.linear4 = nn.Linear(1024, 95)
        self.active = nn.ReLU()
        self.reg = nn.LogSoftmax(dim=1)
    def forward(self, x):
        x = self.active(self.linear1(x))
        x = self.active(self.linear2(x))
        x = self.active(self.linear3(x))
        x = self.reg(self.linear4(x))
        return x

model = torch.load('model',weights_only=False)
test = torch.tensor(list(range(32,127)),dtype=torch.float32).reshape((95,1))
box = model(test).argmax(dim=1).tolist()
with open('output.txt', 'rb') as f:
    flag = bytes([box.index(i-32)+32 for i in f.read()])
print(flag)
```