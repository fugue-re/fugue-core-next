pub(crate) struct DisjointSet {
    parents: Vec<u32>,
}

impl DisjointSet {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            parents: (0..len).map(|index| index as u32).collect(),
        }
    }

    pub(crate) fn find(&mut self, mut index: usize) -> usize {
        while self.parents[index] as usize != index {
            let parent = self.parents[index] as usize;
            let grandparent = self.parents[parent];
            self.parents[index] = grandparent;
            index = grandparent as usize;
        }
        index
    }

    pub(crate) fn union(&mut self, left: usize, right: usize) {
        let left = self.find(left);
        let right = self.find(right);
        if left != right {
            self.parents[left.max(right)] = left.min(right) as u32;
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.parents.len()
    }
}
