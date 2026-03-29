# Loot

Downloaded files and data from collection phase. Evidence preservation.

## Structure

```
loot/{engagement}/{target_upn}/
  onedrive/       — Files from collect_onedrive
  sharepoint/     — Files from collect_sharepoint
  email/          — Mailbox exports from collect_email
  teams/          — Teams messages from collect_teams
  manifest.md     — What was collected, when, from whom
```

## Auto-populated by

| Tool | What Gets Saved |
|------|----------------|
| `collect_onedrive` | File listings + downloaded files |
| `collect_sharepoint` | Site users, groups, downloaded files |
| `collect_teams` | Team listings + messages |
| `collect_email` | OWA session data |
