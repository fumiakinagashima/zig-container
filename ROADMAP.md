# ロードマップ

進め方・ブログ執筆ルールは `CLAUDE.md` を参照。

## 環境構築（記事化なし）

- [x] `zig init` ベースの最小CLI雛形（`build.zig` / `src/main.zig`）

## フェーズ

- [x] 1. 自前syscallラッパーの設計方針（`std.os.linux`の現状と対処）
  - 実装・動作確認は完了（`src/linux.zig`: `getUname`/`setHostname`）。記事化はせず、以後のnamespace/cgroup/pivot_root実装で`linux.zig`を随時更新し、ボリュームが出た段階でまとめて記事化する
- [x] 2. コンテナ用語集（namespace/cgroup/OCI関連の基礎用語まとめ、以後随時更新）
  - 記事: [Zig: トイコンテナランタイム - 用語集](https://alcogy.co.jp/tech/articles/zig-container-appendix-glossary)
- [ ] 3. `fork`/`clone`で最小プロセス起動＋PID namespace
- [ ] 4. UTS namespaceでホスト名分離
- [ ] 5. Mount namespaceと`pivot_root`
- [ ] 6. IPC namespace
- [ ] 7. rootfs構築（busybox等での最小ファイルシステム）
- [ ] 8. cgroup v2によるリソース制限（CPU/メモリ）
- [ ] 9. Network namespaceとveth構築
- [ ] 10. capabilities/seccompによる権限制御
- [ ] 11. OCI runtime spec準拠のCLI設計（config.json）
- [ ] 12. OCI Distribution APIからのイメージpull（認証・manifest取得）
- [ ] 13. イメージlayerの展開とrootfs化
- [ ] 14. コンテナのライフサイクル管理（create/start/stop/delete）＋ User namespaceによるrootless対応

このあとは区切りをつけず、必要に応じて機能追加（OverlayFS対応、hooks、checkpoint/restore等）をフェーズとして随時追加していく。
