# Git 版本管理指南（小白版）

> 本项目的远程仓库：`https://github.com/PULICE/2026ljzyfan.git`

---

## 目录

1. [必备概念](#1-必备概念)
2. [日常开发流程](#2-日常开发流程)
3. [在新电脑上拉取代码](#3-在新电脑上拉取代码)
4. [修改代码后提交推送](#4-修改代码后提交推送)
5. [拉取他人的修改](#5-拉取他人的修改)
6. [版本标签说明](#6-版本标签说明)
7. [常见问题](#7-常见问题)

---

## 1. 必备概念

### 三个区域

```
工作区（你正在改的代码）
    ↓ git add
暂存区（准备好要提交的文件）
    ↓ git commit
本地仓库（已经保存的一个版本）
    ↓ git push
远程仓库（GitHub 上的备份）
```

- **工作区**：你电脑上看到的文件，正在修改的地方
- **暂存区**：临时存放你想提交的文件
- **本地仓库**：已经保存到 `.git` 里的历史版本
- **远程仓库**：GitHub 上的备份，换电脑也能拉下来

### 几个常用词

| 术语 | 大白话 |
|------|--------|
| `commit` | 保存一个版本（就像游戏存档） |
| `push` | 把本地版本上传到 GitHub |
| `pull` | 从 GitHub 下载最新的版本到本地 |
| `tag` | 给某个版本打个标签（比如 v1.0.0） |
| `branch` | 分支，可以理解成平行时空 |

---

## 2. 日常开发流程

### 原则：只在 master 分支上改

本项目简单，你只需要在 **master** 分支上修改就行了。

### 标准三步走

每次修改代码后，执行这三条命令：

```bash
# 第1步：把修改的文件加入暂存区
git add .

# 第2步：保存为一个版本（引号里写你改了啥）
git commit -m "本次修改的说明"

# 第3步：上传到 GitHub
git push
```

> **注意**：第1次推送需要设置远程仓库，已经设置好了，以后不用再设。

---

## 3. 在新电脑上拉取代码

### 3.1 第一次在新电脑上使用

#### 步骤1：安装 Git

- Windows：从 https://git-scm.com/download/win 下载安装
- 安装时一路"下一步"即可

#### 步骤2：配置身份（只需做一次）

打开终端（cmd 或 PowerShell），运行：

```bash
git config --global user.name "你的名字"
git config --global user.email "你的邮箱@example.com"
```

> 名字和邮箱随便写，但建议跟你 GitHub 账号一致。

#### 步骤3：克隆项目到本地

```bash
git clone https://github.com/PULICE/2026ljzyfan.git
```

这会把整个项目下载到你当前目录下的 `2026ljzyfan` 文件夹里。

#### 步骤4：进入项目目录

```bash
cd 2026ljzyfan
```

现在你就可以在本地修改代码了。

### 3.2 查看所有历史版本

```bash
# 查看提交历史
git log --oneline

# 查看所有标签（版本号）
git tag

# 切换到某个版本看看（只是看看，不改）
git checkout v0.1.0

# 切回最新的代码
git checkout master
```

---

## 4. 修改代码后提交推送

### 完整流程（每次改完代码都这样做）

```bash
# 1. 看看改了哪些文件（确认一下）
git status

# 2. 把所有修改加入暂存区
git add .

# 3. 提交为一个版本（写清楚改了啥）
git commit -m "修复了XXX问题"

# 4. 推送到 GitHub
git push
```

### 示例

比如你改了 `src/main.cpp`，想保存这次修改：

```bash
git add .
git commit -m "优化了时间戳解析逻辑"
git push
```

### 只想提交某个文件

```bash
git add src/main.cpp          # 只提交这一个文件
git commit -m "修改了main.cpp"
git push
```

---

## 5. 拉取他人的修改

> 如果换了一台电脑继续开发，或者别人改了代码，需要先拉取最新版本。

```bash
# 从 GitHub 下载最新代码并合并到本地
git pull
```

**重要**：`git pull` 应该在每次修改代码**之前**先执行一次，确保你是在最新代码上修改。

### 新电脑上的完整工作流

```bash
# 1. 首次克隆（只需要做一次）
git clone https://github.com/PULICE/2026ljzyfan.git
cd 2026ljzyfan

# 2. 每天开始工作前，拉取最新代码
git pull

# 3. 修改代码...

# 4. 提交并推送
git add .
git commit -m "今天改的内容"
git push
```

---

## 6. 版本标签说明

当前已有的版本标签：

| 标签 | 说明 |
|------|------|
| `v0.1.0` | 初始基线版本（项目起点） |

以后发布重要版本时，我会打上新的标签，比如：
- `v0.2.0` — 新增功能
- `v0.3.0` — 更多功能
- `v1.0.0` — 正式版

查看所有标签：

```bash
git tag
```

---

## 7. 常见问题

### Q1: `git push` 要我输入用户名密码？

第一次推送会弹出浏览器窗口让你登录 GitHub。登录一次后 Windows 会记住，以后就不用再输了。

如果弹出的是"输入用户名密码"的对话框：
- 用户名：你的 GitHub 账号
- 密码：不是登录密码！要去 GitHub 生成一个 **Personal Access Token**（个人访问令牌）

生成 Token 的方法：
1. 打开 https://github.com/settings/tokens
2. 点 **Generate new token (classic)**
3. 勾选 `repo` 权限
4. 生成后复制那段字符串，粘贴到密码框

### Q2: `git pull` 提示冲突怎么办？

如果提示 `merge conflict`，说明你和远程仓库改了同一个文件的同一行。

解决方法：
1. 打开提示冲突的文件，会看到类似这样的标记：
   ```
   <<<<<<< HEAD
   你的修改
   =======
   远程的修改
   >>>>>>> origin/master
   ```
2. 手动删除这些标记，保留正确的内容
3. 保存文件后执行：
   ```bash
   git add .
   git commit -m "解决冲突"
   git push
   ```

### Q3: 改错了想撤销？

```bash
# 还没 git add：放弃工作区的修改
git checkout -- 文件名

# 已经 git add 但还没 git commit：撤出暂存区
git reset HEAD 文件名

# 已经 git commit 但还没 git push：撤销本次提交
git reset --soft HEAD~1
```

### Q4: 如何只看某次修改了哪些文件？

```bash
# 看最近一次提交改了啥
git show --stat

# 看某个标签对应的修改
git show v0.1.0
```

---

## 速查卡片

| 场景 | 命令 |
|------|------|
| 新电脑上下载代码 | `git clone https://github.com/PULICE/2026ljzyfan.git` |
| 拉取最新代码 | `git pull` |
| 查看修改状态 | `git status` |
| 添加所有修改 | `git add .` |
| 保存版本 | `git commit -m "说明"` |
| 上传到 GitHub | `git push` |
| 查看历史 | `git log --oneline` |
| 查看所有标签 | `git tag` |
