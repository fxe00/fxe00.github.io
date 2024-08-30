---
title: Guides for Blog
published: 2024-04-01
description: "How to use & write this blog template."
image: "./cover.jpeg"
tags: ["Guide"]
category: Guide
draft: false
---

> 封面源 : [Source](https://image.civitai.com/xG1nkqKTMzGDvpLrqFT7WA/208fc754-890d-4adb-9753-2c963332675d/width=2048/01651-1456859105-(colour_1.5),girl,_Blue,yellow,green,cyan,purple,red,pink,_best,8k,UHD,masterpiece,male%20focus,%201boy,gloves,%20ponytail,%20long%20hair,.jpeg)

这个博客模板是用[Astro](https://astro.build/)建立的。对于指南中没有提到的事情，可以在[Astro Docs](https://docs.astro.build/)中找到答案。[^1]

## pnpm
| command                            | 备注                 |
| ---------------------------------- | -------------------- |
| pnpm run build && pnpm run preview | 预览构建后的静态文件 |
| pnpm run dev                       | 启动本地开发模式     |
| pnpm run publish                   | 推送到仓库           |


## 页前置

```yaml
---
title: My-Blog        # 标题 
published: 2023-09-09 # 发布日期
description: example  # 文章简述
image: ./cover.jpg    # 文章封面: 通过网络/本地文件进行引入
tags: [Foo, Bar]      # 标签
category: Front-end   # 分类
draft: false          # 是否为草稿[true/false]
---
```

### 草稿
dratf为 `true` 的文章被认定为草稿, 草稿不会展示在主页上
```
---
title: Draft Example
published: 2022-07-01
tags: [Markdown, Blogging, Demo]
category: Examples
draft: true
---
```

## 文章内容
### MarkDown拓展功能
#### Github仓库卡片引入
`::github{repo="<owner>/<repo>"}`

::github{repo="shadow1ng/fscan"}

#### 默认警告类型
默认警告类型支持: `note` `tip` `important` `warning` `caution`
:::note
Highlights information that users should take into account, even when skimming.
:::

:::tip
Optional information to help a user be more successful.
:::

:::important
Crucial information necessary for users to succeed.
:::

:::warning
Critical content demanding immediate user attention due to potential risks.
:::

:::caution
Negative potential consequences of an action.
:::

#### 自定义警告类型
:::note[MY CUSTOM TITLE]
This is a note with a custom title.
:::

> [!TIP]
> [The GitHub syntax](https://github.com/orgs/community/discussions/16925) is also supported.

### 链接
链接示例: [link](https://fxe00.github.io/posts/guide/)

回到指定的标题
[section heading in the current doc](#pnpm).

### 插入图片
本地引入: `![image](./img/xxx.jpg)`
![image](./cover.jpeg)

网络引入: `![image](https://xxx.jpg)`


### 引入视频
只需从YouTube或其他平台复制嵌入代码，并粘贴到markdown文件中。

`YouTube`
```
<iframe width="100%" height="468" src="https://www.youtube.com/embed/5gIf0_xpFPI?si=N1WTorLKL0uwLsU_" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
```
`Bilibili`
<iframe width="100%" height="468" src="//player.bilibili.com/player.html?bvid=BV1fK4y1s7Qf&p=1" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"> </iframe>


[^1]: https://docs.astro.build/