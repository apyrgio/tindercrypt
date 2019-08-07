# Abandon all hope, ye who enter here

## Table of contents

* [Why a third document?](#why-a-third-document)
* [Why use an SPDX identifier?](#why-use-an-spdx-identifier)
* [Why this copyright?](#why-this-copyright)
  * [Why use a copyright in the first place?](#why-use-a-copyright-in-the-first-place)
  * [Why use this copyright format?](#why-use-this-copyright-format)
  * [Why not use the copyright symbol?](#why-not-use-the-copyright-symbol)
  * [Why state only the year of creation?](#why-state-only-the-year-of-creation)
  * [Who are the Tindercrypt contributors?](#who-are-the-tindercrypt-contributors)
* [Why this license?](#why-this-license)
  * [Why do we need a license in the first place?](#why-do-we-need-a-license-in-the-first-place)
  * [Which are the most common licenses?](#which-are-the-most-common-licenses)
  * [Why were they not chosen?](#why-were-they-not-chosen)
  * [Why pick MPL-2.0?](#why-pick-mpl-20)
* [Why is the legal notice not attached to every file?](#why-is-the-legal-notice-not-attached-to-every-file)
* [Footnotes](#footnotes)

## Why a third document?

This repo has two legal documents; the [`NOTICE.md`] file, that contains the
copyright and the license header, and the [`LICENSE`] file, that contains the
license in full.

For most people, these documents may seem as standard procedure; walls of
legalese that you find somewhere and you can copy-paste in your code.
Unfortunately, there's no authoritative place that explains how you should
license and/or copyright your FOSS project. Instead, there's incomplete and
oft-times contradicting advice scattered all over the Internet, that you have to
double-check against other sources to see if it's outdated, or if it even makes
sense for FOSS. Also, you can't simply copy what big FOSS projects do either,
because for the same license and language, each project may do different things,
potentially wrong (shocking, I know).

This document, while not legal, serves to explain why we chose this copyright
and license. It's practically a log of all the questions I had while reading on
this subject, and the best answers that I could find, based on various legal or
dev sites. Amusingly, in some questions, many answers were both correct and
wrong at the same time, depending on how you interpreted things! Well, not
amusingly. Unless your idea of fun is to read legal texts until ichor drips from
your eye sockets.

Before we begin, I begrudgingly have to state the following typical disclaimers;
I am not a lawyer ([IANAL]), this is not a legal advice, and if the fact that I
have to chant these incantations does not prove how trigger-happy everyone seems
to be in the legal realm, I am not sure what else will.

All aboard!

## Why use an SPDX identifier?

[SPDX] identifiers are used so that others don't need to check if the license
you cite is the official one, or one slightly modified. This is not the case
with this project, but this identifier helps clarifying any doubts.

Don't get too happy though and attempt to throw the legal stuff away and just
keep this identifier. The existence of an SPDX identifier does not imply that
the license header or copyright notice can be omitted [1]. Yay, more
boilerplate...

## Why this copyright?

There's a lot to unpack here. We'll break this question down into the following
questions:

### Why use a copyright in the first place?

Copyright notices are no longer legally required, but they help in the
following cases [2] [3]:

* To prevent infringers from claiming that they didn't know that the work was
  copyrighted.
* To record which people should grant their permission in order to change the
  project's license.
* To provide attribution to authors of third-party code that has been copied to
  this project.
* To explicitly state the dates of publications.

**Fun fact!** the [Servo] project, which is a very large Rust and MPL-2.0
project, does not specify a copyright notice for the project or its Rust code.

### Why use this copyright format?

You've probably seen variations of this copyright format in other projects too,
but something is always a bit different. Sometimes more than one year is
specified, sometimes only the company or the author is specified, sometimes
a `(C)` creeps in. So, which variation is correct?

GNU proposes the following format for its GPL v3.0 license in its [How to Apply
These Terms to Your New Programs] section:

```
Copyright (C) <year>  <name of author>
```

The Apache license proposes a similar format in its [How to apply the Apache
License to your work] section:

```
Copyright [yyyy] [name of copyright owner]
```

GNU strikes again with [an alternative copyright format], that takes
modifications into consideration:

```
Copyright (C) year1, year2, year3 copyright-holder
```

And an [oft-cited article] ups the ante with this behemoth:

```
Copyright [year project started] - [current year], [project founder] and the
[project name] contributors.
```

So, which variation is correct? Depends! The first is technically wrong if more
than one contributors exist. The third contains additional years of
publication which, while common, are not explicitly covered by the current
copyright law. The fourth specifies year ranges, which don't cover the case
of gaps, i.e., years with none or trivial changes.

In our case, we use the copyright format of the Apache license. Keep on reading
for an equally exciting rationale behind each piece of the copyright format.

### Why not use the copyright symbol?

Both the copyright symbol `(C)` and the `All rights reserved` phrase are relics
of the past [4] [5]. They are confusing and we should stop using them.

Note that many people confusingly equate the absence of the copyright symbol
with the absence of a copyright notice. This is wrong. Even when copyright
notices were legally required, they were valid as long as they used the word
"Copyright" [6].

### Why state only the year of creation?

Some copyright formats keep a log with the years that a file was edited. The
perceived benefit is that subsequent changes will not be back-dated, thus the
copyright will last longer.

This may work for slowly-revised works such as books, but it's different in
software:

First, the pre-1989 copyright law does not expressly permit multiple years [7]
[8]. Granted, it's a common practice, but most probably redundant by now.

Second, non-trivial changes such as whitespace fixes do not warrant a bump in
the copyright year [9]. What constitutes as a trivial change is debatable, and
communicating it to the contributors is even more difficult. You'll need to
ensure that they don't needlessly update the copyright, forget to do so when
they must, or erroneously use a different year. It's not nice risking the
validity of your copyrights due to typos.

Third, in a FOSS project that uses Git, it will always be more accurate to find
the years that a file or the project was modified, with the following command:

```shell
$ git log --pretty=format:"%cd" --date=format:"%Y" | sort -u
2012
2014
2019
```

Whether git commands hold as legal exhibits is a different story.

Fourth, almost all countries protect copyrighted work for at least 50 years
after the author's death [10]. Remember, you're not writing "Lord of the Rings",
you're writing FOSS [11]. Your project's shelf life contests that of beer.

### Who are the Tindercrypt contributors?

A common way to log the contributors of a project is to add themselves to an
`AUTHORS` file or to the copyright header of the file they contribute to.
However, this info can easily go out of sync or encourage anti-patterns [12]
[13] so, again, git to the rescue:

```shell
$ git log --pretty=format:"%an <%ae>"  | sort -u
Jane Doe <jane@doe.org>
John Bots <john@bots.org>
```

## Why this license?

In order to explain why we chose a niche license like [Mozilla Public License
2.0 (MPL-2.0)] for this project, first we need to answer why we need a license
in the first place, which are the most common licenses and why none of them fit
the bill.

### Why do we need a license in the first place?

Many people assume that by default, software is free to use, and by putting a
license to it we pose some form of restriction. Actually, it's backwards. By
default, software cannot be used by anyone other than its copyright holder, and
users must ask for their explicit permission [14]. So, if one writes code that
wants to be used by other people, they should pick a license that allows them to
do so, without asking for permission.

### Which are the most common licenses?

We'll use stats from Github, since it's currently the biggest code hosting
platform for FOSS projects. As of writing this, the most common software
licenses in Github [15] are the following:

* MIT (~4M repos, notably Bootstrap, Visual Studio Code, Bitcoin)
* Apache (~1M repos, notably Tensorflow, Kubernetes, Swift)
* GPL family (~1M repos, notably Linux Kernel, Ansible, Signal)
* BSD family (~200k repos, notably Redis, Homebrew)
* LGPL family (~100K repos, notably Ethereum, libvirt)

In the context of Rust, the above numbers become [16]:

* MIT: ~16K repos
* Apache:~4K repos
* GPL family: ~4K repos
* BSD family: ~1K repos
* LGPL family: ~300 repos

**Fun fact!** MIT and GPLv2 licenses do not entirely protect users against legal
action from copyright holders, and are discouraged from being used, at least on
their own [17]. Have this data point in mind for the current state of licensing
in FOSS.

### Why were they not chosen?

Of these licenses, MIT and Apache are generally considered as the most easy to
work with. The Rust language itself and its associated tools are typically
distributed under the MIT/ASL2 license [18]. The majority of the Rust repos also
fall under one of those two licenses, as one can see in the above stats. The
reason these licenses are so easy to work with is because they are "permissive",
i.e., they allow the end user to do virtually anything they want with the code.
This includes distributing a modified version of the code, without disclosing
what modifications were made. This is a subject of endless debates between the
FS and OSS camp and, if this project were to take a position, it would be the
following:

1. Security-sensitive code cannot be fully trusted unless it's open.
2. Security fixes and extensions from third parties would greatly benefit the
   health of this project.

Permissive licenses do not prohibit the above, but they don't enforce them
either, so they emit a weak signal and thus are not useful for this project.
This leaves the MIT, Apache and BSD family of licenses out.

GPL licenses go to great lengths to ensure that the code remains free. They
follow a share-alike approach, that requires any third-party code ("derivative
work") that uses a GPL-licensed code to be licensed as GPL as well. Again, this
is a subject of endless debates between the FS and OSS camp. Ultimately, we
don't mind if this code is used in proprietary contexts, so long as it's open,
so the GPL family of licenses is out.

LGPL licenses are more permissive than GPL licenses. Users of LGPL-licensed
libraries (via dynamic linking) do not have to relicense their software to
LGPL. However, derivative works and executables (via static linking) must
relicense themselves as LGPL. This means that in the Rust ecosystem, which
favors static linking, LGPL licenses are effectively similar to GPL licenses
[19]. This is undesirable for the reasons explained above, so the LGPL family of
licenses is out.

### Why pick MPL-2.0?

Since none of the common licenses fit the bill, we need to turn to less common
ones. A license that is a middle ground between MIT/Apache and (L)GPL is the
Mozilla Public License 2.0 (MPL-2.0). It's a relatively new license (published
in 2012), that is compatible both with the Apache and (L)GPL licenses. There are
~40K repos in Github that use this license, notably Mozilla [Servo] and
Hashicorp [Terraform], and ~900 Rust repos, the latter number being comparable
to the number of BSD and LGPL Rust repos.

The advantage of MPL-2.0 over the aforementioned licenses is that it enforces
that the code will remain always open, without requiring anything else from the
user, besides sharing any modifications they've made to the code. Also, since
it's more modern, it has explicit clauses regarding patent rights and license
compatibilities, making it easier for users and legal departments to comply
with.

## Why is the legal notice not attached to every file?

Before explaining why, let's see what the absence of a copyright and license
notice from a file means for this project from a legal perspective:

* **Absence of copyright:** As mentioned above, copyright is automatic and
  granted to the author the moment they publish their work, so each file would
  belong to its authors.
* **Absence of license:** The code is still licensed under MPL-2.0. The MPL-2.0
  license has a clause that makes the code licensed under it, if the author
  ships a copy of the full MPL-2.0 license with their code [20], which this
  project does.

So, even if a court ruled that the legal notice in [`NOTICE.md`] does not apply
to all files, what would the default legal protection be? The sole difference
would be that the copyright for a file would belong to its authors and not the
project contributors collectively, as stated in [`NOTICE.md`]. This is
cumbersome, but not catastrophic. Other than that, they are effectively the
same.

It would seem that we don't actually need to add the legal notice of [`NOTICE.md`]
to every file in this repo, which is much more sane from a maintenance poin-
**NOT SO FAST, PARTNER!**

The author is still advised to add the per-file boilerplate header, in case
another dev copy-pastes a file of this project to their project, without
checking the root directory for a legal notice [21] [22], and thus claiming that
they didn't know what the copyright/license was. This is commonly called
"innocent infringement".

*Oh cooome on...* Is this the best we can do? Suppose that this was not about
"code repositories" but "poem anthologies". Am I allowed to pick a poem from
someone's anthology, put it in my own anthology and publish it? No. Would it
be reasonable to expect a copyright notice to be prepended before each poem in
the book, so I don't get confused? By Toutatis, no!

Adding a copyright notice **into each part** of a collective work was never a
requirement for books and songs, the very things that copyright law was designed
to protect. Yet somehow, this practice is encouraged in code. Maybe this happens
because lawyers don't read code, as they read books and listen to songs. Or
because they believe that devs will absentmindedly copy-paste a file from a
project without skimming its `README` or home page [23]. Or because this is an
easy task to automate.

Personally, I believe that:

1. Explicitly stating in a single `NOTICE` file what is the legal status of a
   project.
2. Making everyone aware about this file by mentioning it in the `README`.

should make the life of users and contributors much easier, and the legal status
clearer, since there are no omitted or stale file headers.

I also like to believe that there are tools nowadays, such as [FOSSA], that can
help those devs, who in their copy-paste frenzy forget to retain the original
license. Or use a package manager.

Unfortunately, I don't (and hopefully will never) know what are the legal
consequences of not having this legal notice splattered all over the files of
this repo. But...

**Fun fact!** Hashicorp, which happens to be a big MPL-2.0 user, does not have
per-file boilerplate headers in its projects, e.g., [Terraform]. I don't know
about you, but after this plunge into the sea of legal ambiguity, this is a
comforting thought.

## Footnotes

[1] From https://spdx.org/ids-how:

    SPDX IDs are intending to express information about licenses. Copyright
    notices ‐ statements about who owns the copyright in a file or project ‐ are
    outside the scope of SPDX short-form IDs.

    Therefore, you should not remove or modify existing copyright notices in
    files when adding an SPDX ID.

    ---

    When a license defines a recommended notice to attach to files under that
    license (sometimes called a "standard header"), the SPDX project recommends
    that the standard header be included in the files, in addition to an SPDX
    ID.

[2] From https://softwarefreedom.org/resources/2012/ManagingCopyrightInformation.html:

    Contrary to popular belief, copyright notices aren't required to secure
    copyright. Each developer holds copyright in his or her code the moment it
    is written, and because all the world's major copyright systems—including
    the US after 1976—do not require notices, publishing code without a
    copyright notice doesn't change this. However, notices do have some legal
    effect. For example, someone who infringes the copyright of a program
    published without a notice may be able to claim that the infringement was
    "innocent" because he or she had no notice of the developers' copyright
    claim, and thus seek reduced damages.

    There are other good reasons to include copyright notices as well. They
    acknowledge the developers' contributions to the project. They also serve as
    a record of people who claim rights in the codebase, which may be needed if
    the project later wishes to seek the contributors' permission to change its
    license. Finally, when you incorporate third-party free software into your
    project, you must include the corresponding copyright notices—nearly every
    free software license requires it.

[3] From https://ben.balter.com/2015/06/03/copyright-notices-for-websites-and-open-source-projects/:

    Historically, the primary point of putting copyright on anything is because
    in ye olden days (before 1979), it was a legal requirement that a publisher
    visually mark their work in order to secure their copyright under the
    United States Copyright Act. After the US became a signatory of the Berne
    convention (along with 167 other countries), that requirement was dropped,
    and copyright now automatically vests in the author at the time of
    publication in the vast majority of countries, notice or no notice.

    Today, explicit copyright notices in licenses, footers (or really in
    general), are not necessary for getting a copyright. They still have some
    uses, though. First, someone may want to use your work in ways not allowed
    by your license; notices help them determine who to ask for permission.
    Explicit notices can help you prove that you and your collaborators really
    are the copyright holders. They can serve to put a potential infringer on
    notice by providing an informal sniff test to counter the "Oh yeah, well I
    didn't know it was copyrighted" defense. For some users the copyright
    notice may suggest higher quality, as they expect that good software will
    include a notice. A notice may also help people determine when copyright
    might expire, but the date is ambiguous at best, and I'd suspect we'll have
    better ways to determine the date of publication 80+ years from now, if
    your code is still worth protecting. Git can track these things, but people
    may receive software outside of git or where the git history has not been
    retained.

[4] https://www.plagiarismtoday.com/2015/08/18/the-bizarre-history-of-all-rights-reserved/

[5] https://www.plagiarismtoday.com/stopping-internet-plagiarism/your-copyrights-online/3-copyright-myths/

[6] From https://en.wikipedia.org/wiki/Copyright_symbol#Pre-1989_U.S._copyright_notice:

    In the United States, the copyright notice required prior to March 1, 1989,
    consists of ... the `(C)` symbol, or the word "Copyright" or abbreviation
    "Copr.";

[7] https://danashultz.com/2013/10/09/copyright-notice-with-multiple-years-legitimate/

[8] https://techwhirl.com/updating-copyright-notices/

[9] From https://www.gnu.org/prep/maintain/html_node/Copyright-Notices.html:

    To update the list of year numbers, add each year in which you have made
    nontrivial changes to the package.

    ---

    You can use a range (‘2008-2010’) instead of listing individual years
    (‘2008, 2009, 2010’) if and only if: 1) every year in the range, inclusive,
    really is a “copyrightable” year that would be listed individually;

[10] From https://www.wipo.int/treaties/en/ip/berne/summary_berne.html:

     As to the duration of protection, the general rule is that protection must
     be granted until the expiration of the 50th year after the author's death.

[11] https://stackoverflow.com/a/20911485

[12] From https://opensource.com/law/14/2/copyright-statements-source-files:

     * If I edit a file and it says at the top that the file is copyright BigCo,
       I am discouraged from editing that file, because of the implication that
       I'm treading on someone else's toes. Files should not have any indication
       that they are "owned" by any one person or company. (See this by Karl
       Fogel for more on "owning" code.) This actively discourages people
       jumping in and fixing stuff.
     * If N people contribute to a file, are we supposed to have N copyright
       statements in the file? This doesn't scale over time. Imagine what these
       files will look like 10 years from now, and fix the problem now.
     * Having author names in a file encourages people to contribute for the
       wrong reasons.
     * Git keeps track of who contributed what changes. It's not necessary to
       have explicit copyright statements.

[13] https://git.savannah.gnu.org/cgit/guix.git/tree/gnu/packages/python-xyz.scm

[14] https://choosealicense.com/no-permission/

[15] Stats taken by Github with the following queries:

* MIT: license:mit
* Apache: license:apache-2.0
* GPL: license:gpl
* BSD: license:bsd-2-clause and license:bsd-3-clause
* LGPL: license:lgpl
* MPL-2.0: license:mpl-2.0

[16] We simply add the `language:rust` search filter to the `license:...`
     filters mentioned in [15].

[17] From http://worthhiding.com/2018/01/18/licenses-loopholes-and-litigation-a-comprehensive-survey-of-software-case-law-and-open-source-licensing-in-the-united-states/:

     Indeed, while GPLv3 and Apache 2.0 are effective at protecting against all
     four mechanisms, GPLv2 left patent grants unaddressed, and the MIT license
     left both patents and object code copyright completely unaddressed.

     Despite its weakness, the MIT license ranks as the most popular in the open
     source community, with 45% of licensed projects on GitHub using it. The
     also-weak GPLv2 is second in GitHub popularity, with 13% of projects.

[18] https://doc.rust-lang.org/1.5.0/complement-project-faq.html#why-a-bsd-style-permissive-license-rather-than-mpl-or-tri-license

[19] https://internals.rust-lang.org/t/cargo-build-certain-dependencies-as-dylibs/4586/5

[20] From https://www.mozilla.org/en-US/MPL/2.0/FAQ/:

     Q22: Does MPL 2.0 require that the MPL 2.0 license notice header be
     included in every file?

     The license notice must be in some way "attached" to each file.
     (Sec. 1.4.) In cases where putting it in the file is impossible or
     impractical, that requirement can be fulfilled by putting the notice
     somewhere that a recipient "would be likely to look for such a
     notice," such as a LICENSE file in the same directory as the file.

     ---

     Q25: What happens if someone doesn't use the per-file boilerplate,
     and just ships a copy of the full MPL 2 with their code?

     The code is licensed under the plain MPL 2. It is not considered
     Incompatible with Secondary Licenses.

[21] From https://lu.is/blog/2012/03/17/on-the-importance-of-per-file-license-information/:

     It is true that in the best case scenario in many modern
     languages/frameworks, library-level is a great place to put licenses – in
     normal use, they'll get seen and understood. But lots of coding in the
     wild is not ""normal use."" I review a lot of different codebases these
     days, and files get separated from their parent projects and directories
     all the time.

[22] From https://www.mozilla.org/en-US/MPL/2.0/FAQ/:

     While the license permits putting the header somewhere other than
     the file itself... putting the license notice in the file is the
     surest way to ensure that recipients are always notified.

[23] In modern languages with first-class support for package managers, this
should almost never happen. Suppose that it happens though. A lot of licenses
propose adding a similar file header:

      Part of Foo project ... read the LICENSE file at the top of this directory

If a dev simply copy-pastes this file to their project, without copying the
LICENSE file, do they mean to use their own LICENSE file? Do they refer to the
license of the Foo project? Which fork of the Foo project?


[`NOTICE.md`]: /NOTICE.md
[`LICENSE`]: /LICENSE
[IANAL]: https://en.wikipedia.org/wiki/IANAL
[SPDX]: https://spdx.org/
[Servo]: https://github.com/servo/servo
[Terraform]: https://github.com/hashicorp/terraform
[FOSSA]: https://fossa.com/
[How to Apply These Terms to Your New Programs]: https://www.gnu.org/licenses/gpl-3.0.html#howto
[How to apply the Apache License to your work]: https://www.apache.org/licenses/LICENSE-2.0.html#apply
[an alternative copyright format]: https://www.gnu.org/prep/maintain/html_node/Copyright-Notices.html
[oft-cited article]: https://ben.balter.com/2015/06/03/copyright-notices-for-websites-and-open-source-projects/
[Mozilla Public License 2.0 (MPL-2.0)]: https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2)
