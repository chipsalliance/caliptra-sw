
# Caliptra 2.0 Branching Strategy

A new branch, named **"main-2.x"**, will be created off of the main branch for Caliptra 2.0 development. This includes changes to ROM, FMC and Runtime.

- The **"main-2.x"** branch will not maintain backward compatibility with 1.x features.
- The **"main-2.x"** branch will adhere to the same rules, policies, and CI pipelines as the main branch.
- Any fixes made to the main (1.x) branch will be forward-ported to the **"main-2.x"** branch. These fixes will be cherry-picked from main to main-2.x to maintain a linear history. This will be a weekly exercise.

As the flow of 1.x fixes slows down or as we approach the point of making a 2.0 release (whichever occurs first), we will switch **"main-2.x"** to become the primary branch. This will be targeted for Nov/Dec 2024. We have two options to achieve this:

### Option X
Rename **"main-2.x"** to **"main"** and rename the older main branch to **"release-1.x"**. The **"release-1.x"** branch will become a long-term servicing branch for 1.x bug fixes, while the **"main"** branch will be the active branch for further 2.0 development.

### Option Y
Fork a branch from the main branch and name it **"release-1.x"**. This will become the long-term servicing branch for 1.x. Reverse integrate **"main-2.x"** into the main branch and deprecate the **"main-2.x"** branch. The main branch will then become the active branch for further 2.0 development.

We can decide between these options later, depending on their complexities.

This strategy strikes a balance between maintaining separate branches for development without backward compatibility and developing in a single branch with `#ifdefs` to support 1.x. It facilitates the 2.0 development, removes unnecessary 1.x compatibility overhead, and ensures ongoing support for the 1.x release.
