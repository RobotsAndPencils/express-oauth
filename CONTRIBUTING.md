# How to Contribute

## Pull Requests

Generally we like to see pull requests that:

-   Maintain the existing code style
-   Are focused on a single change (i.e. avoid large refactoring or style adjustments in untouched code if not the primary goal of the pull request)
-   Have [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)
-   Have tests
-   Do not decrease the current code coverage

## Git Strategy

Use a squash rebase workflow using [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/), and [trunk based branching](https://trunkbaseddevelopment.com).

Squashing "atomic" commits and rebasing them onto main results in a curated git log/history. We might think of squashing commits as an editing exercise, like the changes we might make while proof reading a message, paper, or article before publishing it. This curation is intended to produce a consistent narrative in the git logs, free of implementation details, such as those that are produced while manually testing and revising code.

Following are some questions we might ask to assess the quality of the commit messages that are submitted in a pull-request (PR).

- Do the commits follow [conventions](https://www.conventionalcommits.org/en/v1.0.0/)
- Are the commits easy to understand and reason about? Do they contribute to a greater narrative?
- Will future you be able to reason about the git history by reading through these commit messages?
- Will a new team member without any context, and with no access to you be able to reason about the git history by reading through these commit messages?
- Can we connect the commits to the requirements/bug/feature/ticket they are developed for?
- Would it be easy to debug using `git bisect`?
- If there are conflicts, are they easy to resolve?

Following are some examples:

#### Fetch from an appropriate origin

```Shell
git fetch
git checkout main
```

#### Create a bug/feature branch

`git checkout -b [BRANCH_NAME]`

#### Do your work

Consider writing "atomic" commits (a commit per unit of work) so it's easier to remember what you did at the end of this workflow

#### When you're ready to submit a PR, rebase from main

```Shell
git fetch
git rebase origin/main
```

#### Find the commit hash (SHA) for commit _before_ the first commit you made on this branch

```Shell
git log --oneline

# OR if seeing the author and time helps:
git log --pretty=format:'%C(yellow)%h %C(cyan)%an: %C(reset)%s%C(blue)%d %C(green)%cr%C(reset)'
```

In the following example, my first commit on this branch is: 09bab93, so the commit I'm looking for is, 907835a.

```
4b0d519 (HEAD -> features/init) chore: adds private-true to package.json
533eb56 chore: adds linting rules
b8591b9 chore: adds ADR for screaming architecture
0441e8f chore: adds ADR folder to the root-folders ADR
fdf0ffa chore: adds the src directory, and a README stub
9352acf chore: adds ADR for root folder organization
b9d5521 chore: adds ADR directory and README
9c0601b chore: adds package.lock
167e102 chore: adds gitignore
09bab93 chore: initializes the repo
907835a (origin/main, origin/HEAD, main) chore: creates README
fe56cd3 chore: creates repo
```

#### Perform an interactive rebase to that commit

`git rebase -i [SHA]`

Leave the top entry as "pick", and change the rest of the "pick"'s to "squash". After you `:wq`, you will be given an opportunity to rewrite the commit message.

When you're done the following:
```
pick 09bab93 chore: initializes the repo
pick 167e102 chore: adds gitignore
pick 9c0601b chore: adds package.lock
pick b9d5521 chore: adds ADR directory and README
pick 9352acf chore: adds ADR for root folder organization
pick fdf0ffa chore: adds the src directory, and a README stub
pick 0441e8f chore: adds ADR folder to the root-folders ADR
pick b8591b9 chore: adds ADR for screaming architecture
pick 533eb56 chore: adds linting rules
pick 4b0d519 chore: adds private:true to package.json
# Rebase 907835a..4b0d519 onto 907835a (10 commands)
#
# Commands: ...
```

Would look like this:
```
pick 09bab93 chore: initializes the repo
squash 167e102 chore: adds gitignore
squash 9c0601b chore: adds package.lock
squash b9d5521 chore: adds ADR directory and README
squash 9352acf chore: adds ADR for root folder organization
squash fdf0ffa chore: adds the src directory, and a README stub
squash 0441e8f chore: adds ADR folder to the root-folders ADR
squash b8591b9 chore: adds ADR for screaming architecture
squash 533eb56 chore: adds linting rules
squash 4b0d519 chore: adds private:true to package.json
# Rebase 907835a..4b0d519 onto 907835a (10 commands)
#
# Commands: ...
```

After which you would be presented with a commit message editor populated with all of the commit messages that are being squashed together.

> If you want to prepare your commit message ahead of time, the following command will copy to the clipboard, the commit messages since a commit hash: `git log --pretty=format:'%n%C(red)## %s%C(reset)%n%b' -n $(git rev-list 907835a..HEAD --count --reverse) | pbcopy` where 907835a is the commit hash you would use in the above squashing.

#### Push

```Shell
git branch --set-upstream-to=origin/`git symbolic-ref --short HEAD`
git push

# You need to force push if you pushed previously
git push --force
```

#### If changes occur on main before pushing or merging to main, rebase again

```Shell
git fetch
git rebase origin/main
git push #? --force
```
