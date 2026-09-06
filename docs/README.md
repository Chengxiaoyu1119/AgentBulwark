# 项目资料

`docs/` 只保存项目说明，不参与运行时构建。正式产品、工程和研究文档可以提交；媒体与历史资料单独忽略或归档。

## 目录

- `product/`：产品定位和功能边界。
- `engineering/`：本地启动、接口接入和安全边界。
- `research/`：仍在使用的技术研究结论。
- `media/`：视频、图标等非构建素材，仅本地保存并被 Git 忽略。
- `../legacy/archive/materials/`：历史部署说明、评测材料和旧文档，不被生产入口读取。

`markdown/` 是迁移前的资料快照，已移入 `legacy/archive/materials/历史文档/`。当前可执行入口以根目录 `README.md`、`package.json` 和 `apps/` 源码为准；历史资料不被默认 API、控制台和测试导入。
