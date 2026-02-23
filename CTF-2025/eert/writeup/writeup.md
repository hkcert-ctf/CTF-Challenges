# eert

The obfuscation of C++ string and vector after compiling under O1 optimization is quite severe, but careful debugging can still clarify the logic

Below is the source code for generating questions. If you're confused, you can refer to it for clarification

```cpp
#include<iostream>
#include<string>
#include<vector>
using namespace std;
const string CUSTOM_BASE64_TABLE =
    "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/"; 

// Base64 编码函数（使用自定义表）
string base64_encode_custom(const vector<uint8_t>& data) {
    string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(CUSTOM_BASE64_TABLE[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(CUSTOM_BASE64_TABLE[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
string encrypt(const string& s, uint8_t key) {
    vector<uint8_t> xored;
    for (unsigned char c : s) xored.push_back(c ^ key);
    return base64_encode_custom(xored);
}
struct TreeNode {
    char val;
    TreeNode *left;
    TreeNode *right;
    TreeNode(char v = 0) : val(v), left(NULL), right(NULL) {}
};

TreeNode* buildTree(const string &flag) {
    if (flag.empty()) return nullptr;
    vector<TreeNode*> nodes;
    for (char c : flag) nodes.push_back(new TreeNode(c));

    // 按层次连接左右孩子（完全二叉树）
    int n = nodes.size();
    for (int i = 0; i < n; ++i) {
        int l = 2 * i + 1, r = 2 * i + 2;
        if (l < n) nodes[i]->left = nodes[l];
        if (r < n) nodes[i]->right = nodes[r];
    }
    return nodes[0]; // 根节点
}

// 前序遍历

string tmp1="";
string tmp2="";
void preorder(TreeNode *root) {
    if (!root) return;
    tmp1+=root->val;
    preorder(root->left);
    preorder(root->right);
}

// 中序遍历
void inorder(TreeNode *root) {
    if (!root) return;
    inorder(root->left);
    tmp2+=root->val;
    inorder(root->right);
}
string ans1="UgaVTAYXJCSVJ082PQOVJCGSTCR0PgN0OwF=";
string ans2="M1aKS1l/Swd5NBV8Swp/RSmUL1l7OS1FLw0=";
int main()
{
    char flag[100];
    cout<<"input the flag:"<<endl;
    cin>>flag;
    TreeNode *root = buildTree(flag);
    preorder(root);
    inorder(root);
    tmp1=encrypt(tmp1, 0x7);
    tmp2=encrypt(tmp2, 0x8);
    if(tmp1!=ans1||tmp2!=ans2)
    {
        cout<<"wrong flag"<<endl;
        return 0;
    }
    else{
        cout<<"right flag"<<endl;
    }
    cout<<"最后提交的flag请包裹上flag{}";
    return 0;
}
```



I won't write about base64 and XOR, just reverse the process. Let's write about how preorder and inorder traversal uniquely determine a binary tree
```bash
                  Y
          0              U
     _       4       R       3
   _   7   H   3   _   M   @   5
  7 E R _ 1 N _ 7 R 3 3
```
```cpp
#include <iostream>
#include <string>
#include <unordered_map>
#include <queue>
using namespace std;
unordered_map<char, int> mp; // 存中序下标
string preorder = "NourlaE9kpeVwBYzD31QdTgF";
string inorder  = "lrau9EkoVewpYBzNQ13dDgTF";
int preIndex = 0; // 当前前序下标
struct node
{
    char val;
    node *left, *right;
    node(char v) : val(v), left(nullptr), right(nullptr) {}
};
node* buildTree(int inL, int inR) {
    if (inL > inR) return nullptr; // 递归终止条件
    if (preIndex >= preorder.size()) return nullptr;

    char rootVal = preorder[preIndex++];
    node* root = new node(rootVal);

    int mid = mp[rootVal]; // 在中序中的位置

    root->left = buildTree(inL, mid - 1);
    root->right = buildTree(mid + 1, inR);

    return root;
}
//跑bfs
void levelorder(node *root)
{
    queue<node*>q;
    q.push(root);
    while(!q.empty())
    {
        node * cur=q.front();
        q.pop();
        cout<<cur->val;
        if(cur->left)q.push(cur->left);
        if(cur->right)q.push(cur->right);
    }
}
int main() {

    for(int i=0;i<inorder.size();i++)
    {
        mp[inorder[i]]=i;
    }
    node * root=buildTree(0,inorder.size()-1);
    levelorder(root);
    return 0;
}
```

