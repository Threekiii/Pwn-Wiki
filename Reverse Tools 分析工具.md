# Reverse Tools | 分析工具

## 第 1 章 z3

### 1.1 基本介绍

z3 是 Microsoft Research 开发的高性能定理证明器。 z3 用于许多应用中，例如：软件/硬件验证和测试，约束求解，混合系统分析，安全性，生物学（计算机分析）和几何问题。

著名的二进制分析框架 [angr](https://link.zhihu.com/?target=http%3A//angr.io/) 也内置了一个修改版的 z3。

参考阅读：

- z3：https://github.com/Z3Prover/z3
- z3 API in Python：https://ericpony.github.io/z3py-tutorial/guide-examples.htm
- z3py Namespace Reference：https://z3prover.github.io/api/html/namespacez3py.html

Z3Py 是 Python 中的 z3 API。可以使用 pip 安装二进制分析框架 angr 里内置的修改版 z3：

```
$ pip3 install z3-solver
```

引入 z3：

```
from z3 import *
```

z3 中有 3 种类型的变量，分别是整型 (Int)，实型 (Real) 和向量 (BitVec)。

对于整数类型数据，基本API：

1. Int(name, ctx=None)，创建一个整数变量，name 是名字。
2. Ints (names, ctx=None)，创建多个整数变量，names 是空格分隔名字。
3. IntVal (val, ctx=None)，创建一个整数常量，有初始值，没名字。

对于实数类型的 API 与整数类型一致，向量 (BitVec) 则稍有区别：

1. Bitvec(name,bv,ctx=None)，创建一个位向量，name 是他的名字，bv 表示大小。
2. BitVecs(name,bv,ctx=None)，创建一个有多变量的位向量，name 是名字，bv 表示大小。
3. BitVecVal(val,bv,ctx=None)，创建一个位向量，有初始值，没名字。

### 1.2 快速入门

#### 解不等式

```
x = Int('x')
y = Int('y')
solve(x > 2, y < 10, x + 2*y ==7)
```

```
[y = 0, x = 7]
```

函数 `Int('x')` 创建了一个名为 `x` 的整数变量，表达式 `x + 2 * y == 7` 是一个 z3 约束。函数 `solve` 用于求解，在无解的情况下，会返回 `no solution`。

```
x = Real('x')
solve(x > 4, x < 0)
```

```
no solution
```

#### 简化表达式

```
x = Int('x')
y = Int('y')
print(simplify(x + y + 2*x + 3))
print(simplify(x < y + x + 2))
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
```

```
3 + 3*x + y
Not(y <= -2)
And(x >= 2, 2*x**2 + y**2 >= 3)
```

#### 遍历表达式

```
x = Int('x')
y = Int('y')
n = x + y >= 3
print("num args: ", n.num_args())
print("children: ", n.children())
print("1st child:", n.arg(0))
print("2nd child:", n.arg(1))
print("operator: ", n.decl())
print("op name:  ", n.decl().name())
```

```
num args:  2
children:  [x + y, 3]
1st child: x + y
2nd child: 3
operator:  >=
op name:   >=
```

#### 数学运算

z3提供了所有基本的数学运算， 可以求解非线性多项式约束。

```
x = Real('x')
y = Real('y')
solve(x**2 + y**2 > 3, x**3 + y < 5)
```

```
[y = 2, x = 1/8]
```

#### 精度设置

`set_option` 用于配置 z3 环境。`set_option(precision = 30)` 设置显示结果时使用的小数位数。`?` 标记表示在`1.2599210498?` 中输出被截断。

```
x = Real('x')
y = Real('y')
solve(x**2 + y**2 == 3, x**3 == 2)

set_option(precision=30)
print("Solving, and displaying result with 30 decimal places")
solve(x**2 + y**2 == 3, x**3 == 2)
```

```
[y = -1.1885280594?, x = 1.2599210498?]

Solving, and displaying result with 30 decimal places
[y = -1.188528059421316533710369365015?,
 x = 1.259921049894873164767210607278?]
```

如果是分数，也可以设置为小数显示。

```
x = Real('x')
solve(3*x == 1)

set_option(rational_to_decimal=True)
solve(3*x == 1)

set_option(precision=30)
solve(3*x == 1)
```

```
[x = 1/3]
[x = 0.3333333333?]
[x = 0.333333333333333333333333333333?]
```

#### 网页表示法

Z3Py（网页版）使用数学符号显示公式和表达式，命令 `set_option(html_mode = False)` 使得所有公式和表达式以默认的 Z3Py 表示法显示。

```
x = Int('x')
y = Int('y')
print(x**2 + y**2 >= 1)

set_option(html_mode=False)
print(x**2 + y**2 >= 1)

set_option(html_mode=True)
print(x**2 + y**2 >= 1)
```

```
x**2 + y**2 >= 1
x**2 + y**2 >= 1
x<sup>2</sup> + y<sup>2</sup> &ge; 1
```

### 1.3 布尔逻辑 Boolean Logic

#### 1.3.1 简单布尔约束

Z3支持布尔运算符：`And`, `Or`, `Not`, `Implies` (implication), `If` (if-then-else)。双蕴含符号用 `==` 表示。

```
p = Bool('p')
q = Bool('q')
r = Bool('r')
solve(Implies(p, q), r == Not(q), Or(Not(p), r))
```

```
[q = False, p = False, r = True]
```

#### 1.3.2 Python布尔常量

Python布尔常量 `True` 和 `False` 可用于构建 z3 布尔表达式。

```
p = Bool('p')
q = Bool('q')
print(And(p, q, True))
print(simplify(And(p, q, True)))
print(simplify(And(p, False)))
```

```
And(p, q, True)
And(p, q)
False
```

#### 1.3.3 多项式与布尔约束组合

```
p = Bool('p')
x = Real('x')
solve(Or(x < 5, x > 10), Or(p, x**2 == 2), Not(p))
```

```
[x = -1.4142135623?, p = False]
```

以上代码的求解思路：

- `solve` 函数的三个约束都需要满足，由`Not(p)` 得到 `p` 为 `False`；
- `Or(p, x**2 == 2)`  需要成立，由 `x**2 == 2` 解出 `x = +- sqrt(2)`；
- `Or(x < 5, x > 10)` 需要成立，由 `x < 5` 解出  `x = - sqrt(2)`，即 `-1.4142135623`。

### 1.4 求解器 Solvers

```
x = Int('x')
y = Int('y')

s = Solver()
print(s)

s.add(x > 10, y == x + 2)
print(s)

print("Solving constraints in the solver s ...")
print(s.check())

print("Create a new scope...")
s.push()
s.add(y < 11)
print(s)
print("Solving updated set of constraints...")
print(s.check())

print("Restoring state...")
s.pop()
print(s)
print("Solving restored set of constraints...")
print(s.check())
```

```
[]

[x > 10, y == x + 2]

Solving constraints in the solver s ...
sat

Create a new scope...
[x > 10, y == x + 2, y < 11]
Solving updated set of constraints...
unsat

Restoring state...
[x > 10, y == x + 2]
Solving restored set of constraints...
sat
```

`Solver()` 命令创建一个通用求解器。

- `add()`：添加约束。
- `check()`：检查解决方案。如果找到解决方案，返回`sat`（满足）；如果不存在解决方案，返回 `unsat`（不可满足）。

可以使用 `push` 和 `pop` 命令共享约束：

- `push()`：保存约束。
- `pop()`：删除约束。

### 1.5 基本运算 Arithmetic

#### 1.5.1 数学运算

```
a, b, c = Ints('a b c')
d, e = Reals('d e')
solve(a > b + 2,
      a == 2*c + 10,
      c + b <= 1000,
      d >= e)
```

```
[b = 0, c = 0, e = 0, d = 0, a = 10]
```

#### 1.5.2 表达式简化

```
x, y = Reals('x y')
# Put expression in sum-of-monomials form
t = simplify((x + y)**3, som=True)
print(t)
# Use power operator
t = simplify(t, mul_to_power=True)
print(t)
```

```
x*x*x + 3*x*x*y + 3*x*y*y + y*y*y
x**3 + 3*x**2*y + 3*x*y**2 + y**3
```

### 1.6 向量运算 Machine Arithmetic

#### 1.6.1 位移运算

```
# Create to bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x >> 2 == 3)
solve(x << 2 == 3)
solve(x << 2 == 24)
```

```
[x = 12]
no solution
[x = 6]
```

### 1.7 谜题求解 Puzzles 

#### 1.7.1 购物问题

示例：花 100 美元，买 100 只动物。其中，狗要 15 美元，猫要 1 美元，老鼠要 25 美分。您必须至少购买一个，应该购买多少个？

```python
from z3 import *

# 创建三个整型变量
dog, cat, mouse = Ints('dog cat mouse')
solve(dog >= 1,   # 至少一只狗、一只猫、一只老鼠
      cat >= 1,   
      mouse >= 1, 
      
      # 一共 100 只
      dog + cat + mouse == 100,
      
      # 一共 100 美元
      1500 * dog + 100 * cat + 25 * mouse == 10000)
```

```python
[mouse = 56, cat = 41, dog = 3]
```

#### 1.7.2 数独求解

数独目标是在框中插入数字以仅满足一个条件：每行、每列和 `3x3` 框必须恰好包含一次数字 `1` 到 `9` 。

![img](images/sudoku.png)

```python
from z3 import *

# 创建 9*9 整型变量矩阵
X = [ [ Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ]
      for i in range(9) ]

# 每个单元格包含 1-9 中的值
cells_c  = [ And(1 <= X[i][j], X[i][j] <= 9)
             for i in range(9) for j in range(9) ]

# 每行最多包含 1 个数字
rows_c   = [ Distinct(X[i]) for i in range(9) ]

# 每列最多包含 1 个数字
cols_c   = [ Distinct([ X[i][j] for i in range(9) ])
             for j in range(9) ]

# 每个 3*3 矩阵不含重复数字
sq_c     = [ Distinct([ X[3*i0 + i][3*j0 + j]
                        for i in range(3) for j in range(3) ])
             for i0 in range(3) for j0 in range(3) ]

sudoku_c = cells_c + rows_c + cols_c + sq_c

# 数独实例，使用 0 表示空单元格
instance = ((0,0,0,0,9,4,0,3,0),
            (0,0,0,5,1,0,0,0,7),
            (0,8,9,0,0,0,0,4,0),
            (0,0,0,0,0,0,2,0,8),
            (0,6,0,2,0,1,0,5,0),
            (1,0,2,0,0,0,0,0,0),
            (0,7,0,0,0,0,5,2,0),
            (9,0,0,0,6,5,0,0,0),
            (0,4,0,9,7,0,0,0,0))

instance_c = [ If(instance[i][j] == 0,
                  True,
                  X[i][j] == instance[i][j])
               for i in range(9) for j in range(9) ]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
    m = s.model()
    r = [ [ m.evaluate(X[i][j]) for j in range(9) ]
          for i in range(9) ]
    print_matrix(r)
else:
    print("failed to solve")
```

```python
[[7, 1, 5, 8, 9, 4, 6, 3, 2],
 [2, 3, 4, 5, 1, 6, 8, 9, 7],
 [6, 8, 9, 7, 2, 3, 1, 4, 5],
 [4, 9, 3, 6, 5, 7, 2, 1, 8],
 [8, 6, 7, 2, 3, 1, 9, 5, 4],
 [1, 5, 2, 4, 8, 9, 7, 6, 3],
 [3, 7, 6, 1, 4, 8, 5, 2, 9],
 [9, 2, 8, 3, 6, 5, 4, 7, 1],
 [5, 4, 1, 9, 7, 2, 3, 8, 6]]
```

#### 1.7.3 八皇后之谜

八皇后之谜是将八位国际象棋皇后放在 8x8 棋盘上的问题，这样就不会有两个皇后互相攻击。目标是没有两个皇后共享同一行、列或对角线。

```python
from z3 import *

# 每个皇后都在不同的行，因此使用一个整型变量表示皇后的列位置
Q = [ Int('Q_%i' % (i + 1)) for i in range(8) ]

# 每个皇后的列位置在 1-8 范围内
val_c = [ And(1 <= Q[i], Q[i] <= 8) for i in range(8) ]

# 每列最多一个皇后
col_c = [ Distinct(Q) ]

# 对角线约束
diag_c = [ If(i == j,
              True,
              And(Q[i] - Q[j] != i - j, Q[i] - Q[j] != j - i))
           for i in range(8) for j in range(i) ]

solve(val_c + col_c + diag_c)
```

```python
[Q_3 = 8,
 Q_1 = 4,
 Q_7 = 5,
 Q_8 = 7,
 Q_5 = 1,
 Q_4 = 6,
 Q_2 = 2,
 Q_6 = 3]
```

## 第 2 章 Angr

