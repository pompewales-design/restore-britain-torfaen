# Restore Britain Torfaen website

This is the GitHub/Cloudflare version of the Restore Britain Torfaen website.

- The normal website is public.
- Only `/members` and everything below `/members/` requires the shared members password.
- The password is stored as a Cloudflare Worker Secret called `MEMBERS_PASSWORD` and is not stored in this repository.
- Member login sessions last up to 90 days. Changing the password immediately invalidates sessions created with the old password.

## Updating the website

Edit files in `public/` and push the changes to GitHub. Cloudflare Workers Builds can then deploy the changes automatically.

## Changing the quarterly password

In Cloudflare: Workers & Pages → `shiny-grass-9540` → Settings → Variables and Secrets. Edit the `MEMBERS_PASSWORD` Secret and deploy the change.

Do not put the password into this repository.
