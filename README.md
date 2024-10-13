# code-server-multiuser

## 项目介绍

**code-server-multiuser** 是一个用 Rust 实现的服务端软件，旨在为 [code-server](https://github.com/coder/code-server) 提供多用户支持。通过此项目，您可以为不同的用户创建独立的 code-server 实例，支持用户之间的隔离和多用户并发操作，满足团队协作开发需求。

## 技术栈

- **Rust**：核心服务端逻辑的实现语言，性能高效，安全可靠。
- **Actix**：基于 Rust 的高性能 Web 框架。
- **Docker**：通过容器化实现软件的高效部署与管理。
- **Traefik**：作为反向代理，自动处理多用户的域名路由和 SSL 证书管理。

## 特点

- **多用户支持**：为每个用户提供独立的开发环境，互不干扰。
- **容器化部署**：通过 Docker 实现便捷地安装和部署，减少复杂的环境配置。
- **自动化路由**：利用 Traefik 实现动态路由和 SSL 证书的自动管理，让多用户访问更方便、更安全。

## License

该项目使用 MIT License，详情请查看 LICENSE 文件。