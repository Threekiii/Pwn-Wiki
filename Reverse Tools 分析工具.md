# Reverse Tools | 分析工具

## 第 1 章 z3

### 1.1 基本介绍

z3 是 Microsoft Research 开发的高性能定理证明器。 z3 用于许多应用中，例如：软件/硬件验证和测试，约束求解，混合系统分析，安全性，生物学（计算机分析）和几何问题。

著名的二进制分析框架 [Angr](https://link.zhihu.com/?target=http%3A//Angr.io/) 也内置了一个修改版的 z3。

参考阅读：

- z3：https://github.com/Z3Prover/z3
- z3 API in Python：https://ericpony.github.io/z3py-tutorial/guide-examples.htm
- z3py Namespace Reference：https://z3prover.github.io/api/html/namespacez3py.html

Z3Py 是 Python 中的 z3 API。可以使用 pip 安装二进制分析框架 Angr 里内置的修改版 z3：

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

### 2.1 快速开始

#### 2.1.1 安装 Angr

Angr 是 Python 3.8+ 的库，必须先安装到 Python 环境中才能使用。

```
pip install Angr
```

#### 2.1.2 前置知识

32 位系统与 64 位系统的数据类型对比：

| 数据类型       | 说明           | 32位字节数 | 64位字节数 | 取值范围                             |
| -------------- | -------------- | ---------- | ---------- | ------------------------------------ |
| bool           | 布尔型         | 1          | 1          | true，false                          |
| char           | 字符型         | 1          | 1          | -128~127                             |
| unsigned char  | 无符号字符型   | 1          | 1          | 0~255                                |
| short          | 短整型         | 2          | 2          | -32768~32767                         |
| unsigned short | 无符号短整型   | 2          | 2          | 0~65535                              |
| int            | 整型           | 4          | 4          | -2147483648~2147483647               |
| unsigned int   | 无符号整型     | 4          | 4          | 0~4294967295                         |
| long           | 长整型         | 4          | 8          | –                                    |
| unsigned long  | 无符号长整型   | 4          | 8          | –                                    |
| long long      | 长整型         | 8          | 8          | -2^64~2^64-1                         |
| float          | 单精度浮点数   | 4          | 4          | 范围-2^128~2^128 精度为6~7位有效数字 |
| double         | 双精度浮点数   | 8          | 8          | 范围-2^1024~2^1024 精度为15~16位     |
| long double    | 扩展精度浮点数 | 8          | 8          | 范围-2^1024~2^1024 精度为15~16位     |
| *              | 地址           | 4          | 8          | –                                    |

指针的大小与其指向的内存中存储的变量类型无关，它只与计算机操作系统有关，在 32 位操作系统中，指针的大小是 4 字节；64 位操作系统中，指针的大小是 8 个字节。

#### 2.1.3 参考阅读

- 官方文档：https://docs.Angr.io/en/latest/
- Angr_ctf：https://github.com/jakespringer/Angr_ctf

### 2.2 核心概念

#### 2.2.1 加载项目 Project

以 Angr_ctf 中的 [00_Angr_find](https://github.com/jakespringer/Angr_ctf/blob/master/dist/00_Angr_find) 为例。将二进制文件 `00_Angr_find` 加载到项目中：

```python
import Angr      
proj = Angr.Project("./00_Angr_find")
```

载入二进制文件后，可以访问关于项目的一些基本属性：

- arch：CPU 架构
- entry： 文件入口点地址
- filename：文件名

```python
import Angr
import monkeyhex      
proj = Angr.Project("./00_Angr_find")
print(proj.arch)
print(proj.entry)
print(proj.filename)
```

```
# 输出
<Arch X86 (LE)>
134513744
./00_Angr_find
```

#### 2.2.2 project.loader

通过 `.loader` 属性，可以获得二进制文件的共享库、地址空间、是否存在可执行栈等信息：

```
>>> proj.loader
<Loaded true, maps [0x400000:0x1007fff]>

>>> proj.loader.shared_objects
{'true': <ELF Object true, maps [0x400000:0x6063bf]>,
 'libc.so.6': <ELF Object libc-2.23.so, maps [0x700000:0xac999f]>,
 'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0xb00000:0xd27167]>,
 'extern-address space': <ExternObject Object cle##externs, maps [0xe00000:0xe7ffff]>,
 'cle##tls': <ELFTLSObjectV2 Object cle##tls, maps [0xf00000:0xf1500f]>}
 
>>> proj.loader.min_addr
0x400000

>>> proj.loader.max_addr
0x1007fff

>>> proj.loader.main_object
<ELF Object true, maps [0x400000:0x6063bf]>

>>> proj.loader.main_object.execstack
False

>>> proj.loader.main_object.pic
False
```

#### 2.2.3 project.factory

##### blocks

`block()` 用于从给定地址提取基本代码块。`block.pp()` 可以格式化输出。

```
>>> block = proj.factory.block(proj.entry)

>>> block.pp()	
        _start:
4013d0  xor     ebp, ebp
4013d2  mov     r9, rdx
4013d5  pop     rsi
4013d6  mov     rdx, rsp
4013d9  and     rsp, 0xfffffffffffffff0
4013dd  push    rax
4013de  push    rsp
4013df  mov     r8, 0x403fc0
4013e6  mov     rcx, 0x403f50
4013ed  mov     rdi, 0x401330
4013f4  call    __libc_start_main

>>> block.instructions
0xb

>>> block.instruction_addrs
(0x4013d0,
 0x4013d2,
 0x4013d5,
 0x4013d6,
 0x4013d9,
 0x4013dd,
 0x4013de,
 0x4013df,
 0x4013e6,
 0x4013ed,
 0x4013f4)
```

##### states

在执行时，实际上是对 SimState 对象进行操作，它代表程序的一个实例镜像，模拟执行某个时刻的状态。

```
>>> state = proj.factory.entry_state()
```

SimState 包含程序的内存、寄存器、文件系统数据等。

- `state.regs` ：访问该状态的寄存器
- `state.mem`  ：访问该状态的内存

```
>>> state.regs.rip
<BV64 0x4013d0>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved
<BV32 0x8949ed31>
```

返回的结果都是 BV 类型，并不是 int 类型，BV 是位向量（bitvector）的简称，实际上就是一串比特序列，Angr 使用位向量表示 CPU 数据。

Python 中 int 与 bitvector 的相互转换：

```
>>> bv = state.solver.BVV(0x1234, 32)
<BV32 0x1234>

>>> state.solver.eval(bv)
0x1234
```

可以将这些位向量存储到寄存器/内存，也可以直接存储 int 类型，再将其转换为对应大小的位向量：

```
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

##### simulation managers

simulation managers 用于管理 state，执行运行、模拟等操作。

```
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x4013d0>]
```

```
>>> simgr.step()
<SimulationManager with 1 active>
```

```
>>> simgr.active
[<SimState @ 0x401180>]

>>> simgr.active[0].regs.rip
<BV64 0x401180>

>>> state.regs.rip
<BV64 0x4013d0>
```

#### 2.2.4 Analyses

`proj.analyses.` 后通过 TAB 补全以获取内置分析列表：

```
>>> proj.analyses.
proj.analyses.AILBlockSimplifier(          proj.analyses.Propagator(
proj.analyses.AILCallSiteMaker(            proj.analyses.Proximity(
proj.analyses.AILSimplifier(               proj.analyses.ReachingDefinitions(
proj.analyses.BackwardSlice(               proj.analyses.Reassembler(
proj.analyses.BinDiff(                     proj.analyses.RecursiveStructurer(
proj.analyses.BinaryOptimizer(             proj.analyses.RegionIdentifier(
proj.analyses.BoyScout(                    proj.analyses.RegionSimplifier(
proj.analyses.CDG(                         proj.analyses.SootClassHierarchy(
proj.analyses.CFB(                         proj.analyses.StackPointerTracker(
proj.analyses.CFBlanket(                   proj.analyses.StaticHooker(
proj.analyses.CFG(                         proj.analyses.StaticObjectFinder(
proj.analyses.CFGEmulated(                 proj.analyses.StructuredCodeGenerator(
proj.analyses.CFGFast(                     proj.analyses.Typehoon(
proj.analyses.CFGFastSoot(                 proj.analyses.VFG(
proj.analyses.CalleeCleanupFinder(         proj.analyses.VSA_DDG(
proj.analyses.CallingConvention(           proj.analyses.VariableRecovery(
proj.analyses.ClassIdentifier(             proj.analyses.VariableRecoveryFast(
proj.analyses.Clinic(                      proj.analyses.Veritesting(
proj.analyses.CodeTagging(                 proj.analyses.VtableFinder(
proj.analyses.CompleteCallingConventions(  proj.analyses.XRefs(
proj.analyses.CongruencyCheck(             proj.analyses.discard_plugin_preset(
proj.analyses.DDG(                         proj.analyses.get_plugin(
proj.analyses.DataDep(                     proj.analyses.has_plugin(
proj.analyses.Decompiler(                  proj.analyses.has_plugin_preset
proj.analyses.Disassembly(                 proj.analyses.plugin_preset
proj.analyses.DominanceFrontier(           proj.analyses.project
proj.analyses.Flirt(                       proj.analyses.register_default(
proj.analyses.Identifier(                  proj.analyses.register_plugin(
proj.analyses.ImportSourceCode(            proj.analyses.register_preset(
proj.analyses.InitFinder(                  proj.analyses.release_plugin(
proj.analyses.InitializationFinder(        proj.analyses.reload_analyses(
proj.analyses.LoopFinder(                  proj.analyses.use_plugin_preset(
```

### 2.3 CTF 中使用 Angr

一般来说使用 Angr 的具体步骤如下：

1. 创建 project
2. 设置 state
3. 新建符号量 BVS（bitvector symbolic）或 BVV（bitvector value）
4. 将符号量设置到内存或是其他地方
5. 设置 simulation managers
6. 运行，探索满足路径需要的值
7. 约束求解，获取执行结果

#### 2.3.1 创建 project

使用 Angr，首先创建 project，加载二进制文件。

`auto_load_libs` 设置是否自动载入依赖的库，基础题目中一般不分析引入的库文件，设置为 False。

```python
path_to_binary = "./00_Angr_find"
project = Angr.Project(path_to_binary, auto_load_libs=False)
```

#### 2.3.2 设置 state

state 代表程序的一个实例镜像，模拟执行某个时刻的状态。

`project.factory.entry_state()` 使符号执行引擎从程序的入口点开始符号执行。

```python
initial_state = project.factory.entry_state()
```

#### 2.3.3 设置 simulation managers

在执行时，实际上是对 SimState 对象进行操作，它代表程序的一个实例镜像，模拟执行某个时刻的状态。

`SimState` 对象包含程序运行时信息，如内存/寄存器/文件系统数据等。

```python
simulation = 
project.factory.simgr(initial_state)
```

运行，探索满足路径需要的值

符号执行最普遍的操作是找到能够到达某个地址的状态，同时丢弃其他不能到达这个地址的状态。

当使用 `find` 参数启动 `.explore()` 方法时，程序将会一直执行，直到发现了一个和 `find` 参数指定的条件相匹配的状态。

```python
print_good_address = 0x8048678  
simulation.explore(find=print_good_address)
```

#### 2.4.4 约束求解，获取执行结果

此时相关状态已经保存在了 `simgr`，可以通过 `simgr.found` 来访问所有符合条件的分支。

Unix 中的文件描述符：

- sys.stdin.fileno() ：标准输入（0）
- sys.stdout.fileno()：标准输出（1）
- sys.stderr.fileno()：标准错误（2）

所以 `solution_state.posix.dumps(sys.stdin.fileno())` 也可以表示为 `solution_state.posix.dumps(0)`。

```python
if simulation.found:
    # simulation.found[0] 获取通过 explore 找到符合条件的状态
    solution_state = simulation.found[0]  
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
```

### 2.4 加载二进制文件

#### 2.4.1 加载对象

以 [fauxware](https://github.com/Angr/Angr-doc/blob/master/examples/fauxware/fauxware) 为例：

```
>>> import Angr, monkeyhex
>>> proj = Angr.Project('fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x1007fff]>
```

获取加载对象的完整列表：

```
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x700000:0xac999f]>,
 <ELF Object ld-2.23.so, maps [0xb00000:0xd27167]>,
 <ExternObject Object cle##externs, maps [0xe00000:0xe7ffff]>,
 <ELFTLSObjectV2 Object cle##tls, maps [0xf00000:0xf1500f]>,
 <KernelObject Object cle##kernel, maps [0x1000000:0x1007fff]>]
```

其他的一些对象：

```
>>> proj.loader.main_object
>>> proj.loader.all_elf_objects
>>> proj.loader.extern_object
>>> proj.loader.kernel_object
>>> proj.loader.find_object_containing(0x400000)
```

可以直接与对象交互，提取元数据：

```
>>> obj = proj.loader.main_object
>>> obj.entry
>>> obj.min_addr, obj.max_addr
>>> obj.segments
>>> obj.sections
>>> obj.find_segment_containing(obj.entry)
>>> obj.find_section_containing(obj.entry)

>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

>>> obj.reverse_plt[addr]
>>> obj.linked_base
>>> obj.mapped_base
```

#### 2.4.2 符号和重定位

```
>>> strcmp = proj.loader.find_symbol('strcmp')
```

```
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>
```

symbol 对象有三种获取其地址的方式：

- `.rebased_addr`: 在全局地址空间的地址。
- `.linked_addr`: 相对于二进制的预链接基址的地址。
- `.relative_addr`: 相对于对象基址的地址。

```
>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0
```

#### 2.4.3 常见的加载选项

加载二进制文件时一些常见的选项：

- backend：指定 backend
- base_addr：指定基址
- entry_point：指定入口点
- arch：指定架构

```
>>> Angr.Project('fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```

参数 main_opts 和 `lib_opts 接收一个以 python 字典形式存储的选项组。

lib_opts 是二级字典，一个二进制文件可能加载多个库。main_opts 是一级字典，指定的是主程序加载参数，而主程序一般只有一个。

### 2.5 符号表达式和约束求解

#### 2.5.1 位向量 bitvector

符号位向量是 Angr 用于将符号值注入程序的数据类型。这些将是 Angr 将解决的方程式的 `x`，也就是约束求解时的自变量。可以通过 `BVV(value,size)` 和 `BVS( name, size)` 接口创建位向量。

加载一个项目：

```
>>> import Angr, monkeyhex
>>> proj = Angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

创建位向量：

```
# create a 27-bit bitvector with concrete value 9
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

创建符号向量：

```
# Create a bitvector symbol named "x" of length 64 bits
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

符号向量 x 和 y 也是 AST（抽象语法树，Abstract Syntax Tree）。

#### 2.5.2 约束求解 eval

通过约束添加到 state，将强制约束求解器将它们视为必须满足的条件：

```
state.solver.add(x > y)
state.solver.add(y > 2)
state.solver.add(10 > x)
state.solver.eval(x)
4
```

也可以求解表达式：

```
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

#### 2.5.3 浮点数 FPV FPS

可以使用 `FPV` 和 `FPS` 创建浮点值和符号：

```
# fresh state
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

约束和求解以相同的方式工作，但 `eval` 返回一个浮点数：

```
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

#### 2.5.4 常见的约束求解模式

- `solver.eval(expression)` 将提供给定表达式的一种可能解决方案。
- `solver.eval_one(expression)` 将提供给定表达式的解决方案，可能有多个解决方案则抛出异常。
- `solver.eval_upto(expression, n)` 将提供给定表达式的最多 n 个解决方案，如果少于 n 个，则返回 n 个。
- `solver.eval_atleast(expression, n)` 将提供给定表达式的 n 个解决方案，如果少于 n 个，则抛出异常。
- `solver.eval_exact(expression, n)` 将提供给定表达式的 n 个解，如果少于或多于 n 个，则抛出异常。
- `solver.min(expression)` 将提供给定表达式的最小可能解决方案。
- `solver.max(expression)` 将提供给定表达式的最大可能解。

### 2.6 机器状态（内存、寄存器等）

#### 2.6.1 读写内存和寄存器

通过 `state.regs` 对象的属性访问以及修改寄存器的数据，一些简单示例：

```
>>> import Angr, claripy
>>> proj = Angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

从标准输入读取位向量：

```
input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)
```

#### 2.6.2 状态构造函数 state

除了 `project.factory.entry_state()` 外，还有几个状态构造函数：

- `.blank_state()` 构造一个空白状态，其大部分数据未初始化。当访问未初始化的数据时，将返回一个不受约束的符号值。
- `.entry_state()` 构造一个准备好在二进制文件的入口点执行的状态。
- `.full_init_state()` 构造一个已经执行过所有与需要执行的初始化函数，并准备从函数入口点执行的状态。比如，共享库构造函数（constructor）或预初始化器。当这些执行完之后，程序将会跳到入口点。
- `.call_state()`构造一个准备好执行给定函数的状态。

这些构造函数有如下参数：

- 所有构造函数都可以采用 `addr` 参数来指定起始地址。
- 如果在可以接受命令行参数的环境或环境中执行，则可以通过 `args` 传递参数列表，通过 `env` 传递环境变量字典到 `entry_state` 和 `full_init_state` 。
- 可以将符号位向量作为 `argc` 传递给 `entry_state` 和 `full_init_state` 构造函数。
- 可以使用 `.call_state(addr, arg1, arg2, ...)` 调用它，其中 `addr` 是您要调用的函数的地址， `argN` 是该函数的第 N 个参数，可以是 Python 整数、字符串或数组或位向量。

#### 2.6.3 存储器接口 memory

`state.mem` 接口对于从内存中加载类型化数据很方便，但当对内存范围进行原始加载和存储时非常麻烦。`state.mem` 实际上只是一堆正确访问底层内存存储的逻辑，只是一个填充了位向量数据的平面地址空间： `state.memory` 。

可以将 `state.memory` 直接与 `.load(addr, size)` 和 `.store(addr, val)` 方法一起使用：

```
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```

注意，size 是以字节为单位。

### 2.7 模拟管理器 Simulation Manager

#### 2.7.1 状态操作 step / run

模拟管理器最基本的功能是将给定存储中的所有状态向前推进一个基本块。可以使用 `.step()` 执行此操作：

```
>>> import Angr
>>> proj = Angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

可以使用 `.move()` 在存储之间移动状态。例如，移动输出中包含特定字符串的所有内容：

```
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 
```

#### 2.7.2 寻找状态 explore

符号执行中使用 `.explore()` 方法找到到达某个地址的状态，同时丢弃所有经过另一个地址的状态。

当使用 `find` 参数启动 `.explore()` 时，执行将一直运行直到找到与查找条件匹配的状态，该状态可以是要停止的指令地址、要停止的地址列表或函数接受一个状态并返回它是否满足某些条件。一个 CTF 的简单示例如下：

第一步，加载二进制文件。

```
>>> proj = Angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
```

第二步，创建一个 SimulationManager。

```
>>> simgr = proj.factory.simgr()
```

第三步，执行，直到找到符合条件的状态。

```
>>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

第四步，读取 Flag。

```
>>> s = simgr.found[0]
>>> print(s.posix.dumps(1))
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
print(flag)
g00dJ0B!
```

### 2.8 File System / Sockets / Pipes

#### 示例 1：创建具有具体内容的文件

```
>>> import Angr
>>> simfile = Angr.SimFile('myconcretefile', content='hello world!\n')
```

#### 示例 2：创建具有符号内容和定义大小的文件

```
>>> simfile = Angr.SimFile('mysymbolicfile', size=0x20)
>>> simfile.set_state(state)

>>> data, actual_size, new_pos = simfile.read(0, 0x30)
>>> assert data.symbolic
>>> assert claripy.is_true(actual_size == 0x20)
```

SimFile 提供了和 `state.memory` 一样的接口，所以可以直接加载数据：

```
>>> assert simfile.load(0, actual_size) is data.get_bytes(0, 0x20)
```

#### 示例 3：创建具有受限符号内容的文件

```
>>> bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(32)]
>>> bytes_ast = claripy.Concat(*bytes_list)
>>> mystate = proj.factory.entry_state(stdin=Angr.SimFile('/dev/stdin', content=bytes_ast))
>>> for byte in bytes_list:
...    mystate.solver.add(byte >= 0x20)
...    mystate.solver.add(byte <= 0x7e)
```

#### 示例 4：创建一个包含一些混合的具体内容和符号内容但没有 EOF 的文件

```
>>> variable = claripy.BVS('myvar', 10*8)
>>> simfile = Angr.SimFile('mymixedfile', content=variable.concat(claripy.BVV('\n')), has_end=False)
>>> simfile.set_state(state)
```

查询文件中存储的字节数：

```
>>> assert claripy.is_true(simfile.size == 11)
```

读取将生成超过当前边界的附加符号数据：

```
>>> data, actual_size, new_pos = simfile.read(0, 15)
>>> assert claripy.is_true(actual_size == 15)
>>> assert claripy.is_true(new_pos == 15)

>>> assert claripy.is_true(data.get_bytes(0, 10) == variable)
>>> assert claripy.is_true(data.get_bytes(10, 1) == '\n')
>>> assert data.get_bytes(11, 4).symbolic
```

#### 示例 5：创建具有符号大小的文件（ has_end 在这里隐含为真）

```
>>> symsize = claripy.BVS('mysize', 64)
>>> state.solver.add(symsize >= 10)
>>> state.solver.add(symsize < 20)
>>> simfile = Angr.SimFile('mysymsizefile', size=symsize)
>>> simfile.set_state(state)
```

#### 示例 6：使用流 ( SimPackets )

流（标准 I/O、TCP 等）像普通文件一样保存数据，但不支持随机访问。

短读取指当请求 `n` 字节但实际上返回的字节数少于 `n` 的情况。可以使用 SimFileBase 的类 `SimPackets` 来自动启用对短读取的支持。默认情况下，stdin、stdout 和 stderr 都是 SimPackets 对象。

```
>>> simfile = Angr.SimPackets('mypackets')
>>> simfile.set_state(state)
```

SimPackets 中的数据以（数据包数据、数据包大小）的元组形式存储在 `.content` 中：

```
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>)]

>>> simfile.read(0, 1, short_reads=False)
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>), (<BV8 packet_1_mypackets>, <BV64 0x1>)]
```

#### 示例 7：文件系统

`state.fs` 用于模拟文件系统，可以使用 `insert` 、 `get` 和 `delete` 方法在文件系统中存储、加载和删除文件。

使文件以  `/tmp/myfile` 的形式被使用：

```
>>> state.fs.insert('/tmp/myfile', simfile)
>>> assert state.fs.get('/tmp/myfile') is simfile
```

挂载文件系统：

```
>>> state.fs.mount('/', Angr.SimHostFilesystem('./guest_chroot'))
```

### 2.9 Hook 和 SimProcedures

#### 2.9.1 基本概念

默认情况下，Project 尝试使用称为 SimProcedures 的符号摘要来替换对库函数的外部调用。

Angr 在每一步检查当前地址是否已被 Hook，如果是，则在该地址运行 Hook 而不是二进制代码。执行此操作的 API 是 `proj.hook(addr, hook)` ，其中 `hook` 是一个 SimProcedure 实例。可以使用 `.is_hooked` 、 `.unhook` 和 `.hooked_by` 来管理项目的 Hook。

```
>>> stub_func = Angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
def my_hook(state):
    state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

此外，可以使用 `proj.hook_symbol(name, hook)` ，提供符号的名称作为第一个参数，来 Hook 符号所在的地址。

#### 2.9.2 Hook 静态编译

静态编译指在编译可执行文件时，把需要用到的对应动态链接库（.so或.ilb）中的部分提取出来，链接到可执行文件中去，使可执行文件在运行时不需要依赖于动态链接库。

动态编译指编译的可执行文件需要附带一个的动态链接库，在执行时，需要调用其对应动态链接库中的命令。

通常，Angr 可以自动使用 SimProcedures 代替标准库函数。但在静态编译的程序中，需要手动 Hook 所有使用标准库的 C 函数。

Angr 已经在 SimProcedure 中提供了这些静态函数，一些常用的函数如下：

```python
Angr.SIM_PROCEDURES['libc']['malloc']
Angr.SIM_PROCEDURES['libc']['fopen']
Angr.SIM_PROCEDURES['libc']['fclose']
Angr.SIM_PROCEDURES['libc']['fwrite']
Angr.SIM_PROCEDURES['libc']['getchar']
Angr.SIM_PROCEDURES['libc']['strncmp']
Angr.SIM_PROCEDURES['libc']['strcmp']
Angr.SIM_PROCEDURES['libc']['scanf']
Angr.SIM_PROCEDURES['libc']['printf']
Angr.SIM_PROCEDURES['libc']['puts']
Angr.SIM_PROCEDURES['libc']['exit']
Angr.SIM_PROCEDURES['glibc']['__libc_start_main']
```

只需手动找到程序中对应静态函数的地址，用 SimProcedure 提供的函数 Hook 掉即可。

```python
project.hook(malloc_address, Angr.SIM_PROCEDURES['libc']['malloc']())
```

#### 2.9.3 Hook 动态编译

Linux 下使用 GCC 将源码编译成可执行文件的过程可以分解为 4 个步骤：预处理（Prepressing）、编译（Compilation）、汇编（Assembly）和链接（Linking）。

动态链接把程序按照模块拆分成相对独立的部分，在程序运行时才将它们链接在一起形成一个完整的程序，而不是像静态链接一样把所有的程序模块都连接成一个单独的可执行文件。ELF动态链接文件被称为动态共享对象（DSO，Dynamic Shared Object），简称共享对象，它们一般都是以 .so 为扩展名的文件。
