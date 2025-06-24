"use client";

import * as React from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useOnClickOutside } from "usehooks-ts";
import { cn } from "@/lib/utils";
import { DivideIcon as LucideIcon } from "lucide-react";

interface Tab {
  title: string;
  icon: LucideIcon;
  type?: never;
}

interface Separator {
  type: "separator";
  title?: never;
  icon?: never;
}

type TabItem = Tab | Separator;

interface ExpandableTabsProps {
  tabs: TabItem[];
  className?: string;
  activeColor?: string;
  onChange?: (index: number | null) => void;
  activeTabIndex?: number | null;
  isDarkMode?: boolean;
}

const buttonVariants = {
  initial: {
    gap: 0,
    paddingLeft: ".75rem",
    paddingRight: ".75rem",
  },
  animate: (isSelected: boolean) => ({
    gap: isSelected ? ".5rem" : 0,
    paddingLeft: isSelected ? "1rem" : ".75rem",
    paddingRight: isSelected ? "1rem" : ".75rem",
  }),
  hover: {
    scale: 1.05,
    transition: { duration: 0.2 }
  }
};

const spanVariants = {
  initial: { width: 0, opacity: 0 },
  animate: { width: "auto", opacity: 1 },
  exit: { width: 0, opacity: 0 },
};

const transition = { delay: 0.1, type: "spring", bounce: 0, duration: 0.6 };

export function ExpandableTabs({
  tabs,
  className,
  activeColor = "text-primary",
  onChange,
  activeTabIndex = null,
  isDarkMode = true,
}: ExpandableTabsProps) {
  const [selected, setSelected] = React.useState<number | null>(null);
  const [hoveredTab, setHoveredTab] = React.useState<number | null>(null);
  const outsideClickRef = React.useRef(null);

  // Update selected based on activeTabIndex prop
  React.useEffect(() => {
    if (activeTabIndex !== null && activeTabIndex !== selected) {
      setSelected(activeTabIndex);
    }
  }, [activeTabIndex, selected]);

  useOnClickOutside(outsideClickRef, () => {
    setSelected(null);
    onChange?.(null);
  });

  const handleSelect = (index: number) => {
    setSelected(index);
    onChange?.(index);
  };

  // Filter out separators to get actual tab indices - no separators now
  const actualTabs = tabs.filter(tab => tab.type !== 'separator') as Tab[];

  return (
    <div
      ref={outsideClickRef}
      className={cn(
        "flex flex-wrap items-center justify-center gap-1 rounded-2xl border bg-background p-2 shadow-lg backdrop-blur-md",
        className
      )}
    >
      {actualTabs.map((tab, index) => {
        const isSelected = selected === index || activeTabIndex === index;
        const isHovered = hoveredTab === index;

        const Icon = tab.icon;
        return (
          <motion.button
            key={tab.title}
            variants={buttonVariants}
            initial="initial"
            animate="animate"
            whileHover="hover"
            custom={isSelected}
            onClick={() => handleSelect(index)}
            onMouseEnter={() => setHoveredTab(index)}
            onMouseLeave={() => setHoveredTab(null)}
            transition={transition}
            className={cn(
              "relative flex items-center rounded-xl py-2.5 text-sm font-medium transition-all duration-300 group",
              isSelected
                ? cn("bg-white/10 shadow-md backdrop-blur-sm", activeColor)
                : isDarkMode 
                  ? "text-white/70 hover:bg-white/5 hover:text-white"
                  : "text-black/70 hover:bg-black/5 hover:text-black"
            )}
          >
            <Icon size={18} className={cn(
              "transition-colors duration-300",
              isSelected 
                ? isDarkMode ? "text-white" : "text-black"
                : isDarkMode ? "group-hover:text-white" : "group-hover:text-black"
            )} />
            
            <AnimatePresence initial={false}>
              {(isSelected || isHovered) && (
                <motion.span
                  variants={spanVariants}
                  initial="initial"
                  animate="animate"
                  exit="exit"
                  transition={transition}
                  className="overflow-hidden whitespace-nowrap ml-2"
                >
                  {tab.title}
                </motion.span>
              )}
            </AnimatePresence>

            {/* Glow effect for active tab */}
            {isSelected && (
              <motion.div
                className={`absolute inset-0 rounded-xl border ${
                  isDarkMode 
                    ? "bg-white/10 border-white/20" 
                    : "bg-black/10 border-black/20"
                }`}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              />
            )}
          </motion.button>
        );
      })}
    </div>
  );
}