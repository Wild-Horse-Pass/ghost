import { useEffect, useMemo, useState } from "react";

export interface Product {
  /// Stable id (random 8-char hex). Survives renames.
  id: string;
  name: string;
  price_sats: number;
  /// Optional emoji shown on the tile. Image upload is a v2 — emojis
  /// give a visual hook today without binary handling.
  emoji?: string;
  description?: string;
  /// Free-form category string. Empty = "Uncategorised". Catalog
  /// derives the filter row from the live set of categories — no
  /// separate management UI required, just type a name and it
  /// becomes a filter automatically.
  category?: string;
}

const STORAGE_PREFIX = "wraith.merchant.products:";

/// Per-wallet product catalog, persisted to localStorage. Returns
/// the live list + a setter that writes through. Hook so multiple
/// components (Merchant + a future settings export) share state.
export function useProducts(walletName: string | null) {
  const key = `${STORAGE_PREFIX}${walletName ?? "_none_"}`;
  const [products, setProducts] = useState<Product[]>(() => {
    if (!walletName) return [];
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(
        (p): p is Product =>
          p &&
          typeof p.id === "string" &&
          typeof p.name === "string" &&
          typeof p.price_sats === "number",
      );
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(products));
    } catch {
      /* quota / sandbox */
    }
  }, [key, products]);

  // When the wallet changes, reload from the new key.
  useEffect(() => {
    if (!walletName) {
      setProducts([]);
      return;
    }
    try {
      const raw = localStorage.getItem(key);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) setProducts(parsed);
      } else {
        setProducts([]);
      }
    } catch {
      setProducts([]);
    }
    // key intentionally excluded — derived from walletName
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletName]);

  return { products, setProducts };
}

interface ProductCatalogProps {
  products: Product[];
  /// Tap-to-add: parent receives the product the user tapped and
  /// folds it into the cart.
  onPick: (p: Product) => void;
  onChange: (next: Product[]) => void;
}

/// Grid of product tiles + a "Manage" button that opens a modal
/// for CRUD. Empty state nudges the user to add their first
/// product. Categories are derived from the live set so adding
/// `category: "Drinks"` to a product auto-creates the filter pill.
export function ProductCatalog({
  products,
  onPick,
  onChange,
}: ProductCatalogProps) {
  const [editing, setEditing] = useState<Product | "new" | null>(null);
  // Active category filter — `null` means "All". Persisted to
  // localStorage so the till stays on the same view between
  // reloads (e.g. after a kiosk restart, the staff are still on
  // the "Drinks" tab).
  const [activeCategory, setActiveCategory] = useState<string | null>(() => {
    try {
      const raw = localStorage.getItem("wraith.merchant.activeCategory");
      return raw && raw !== "" ? raw : null;
    } catch {
      return null;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(
        "wraith.merchant.activeCategory",
        activeCategory ?? "",
      );
    } catch {
      /* quota / sandbox */
    }
  }, [activeCategory]);

  // Distinct, ordered category list — built from products on every
  // render. Cheap (small list) and avoids stale state on edit/add.
  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const p of products) {
      if (p.category && p.category.trim()) set.add(p.category.trim());
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [products]);

  const filtered = activeCategory
    ? products.filter((p) => (p.category ?? "").trim() === activeCategory)
    : products;

  const addProduct = (p: Omit<Product, "id">) => {
    const id =
      typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID().slice(0, 8)
        : Math.random().toString(16).slice(2, 10);
    onChange([...products, { ...p, id }]);
  };
  const updateProduct = (id: string, patch: Partial<Product>) => {
    onChange(products.map((p) => (p.id === id ? { ...p, ...patch } : p)));
  };
  const deleteProduct = (id: string) => {
    onChange(products.filter((p) => p.id !== id));
  };

  return (
    <div className="card till-card-fill">
      <div className="card-header">
        <h2>Products</h2>
        <button
          className="btn-secondary btn-sm"
          onClick={() => setEditing("new")}
        >
          + Add product
        </button>
      </div>
      {categories.length > 0 && (
        <div className="category-row">
          <button
            className={`category-pill${activeCategory === null ? " active" : ""}`}
            onClick={() => setActiveCategory(null)}
          >
            All ({products.length})
          </button>
          {categories.map((cat) => {
            const count = products.filter(
              (p) => (p.category ?? "").trim() === cat,
            ).length;
            return (
              <button
                key={cat}
                className={`category-pill${activeCategory === cat ? " active" : ""}`}
                onClick={() => setActiveCategory(cat)}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>
      )}
      {products.length === 0 ? (
        <p className="muted" style={{ fontSize: 13, margin: 0 }}>
          No products yet. Add coffees, snacks, services — anything
          you sell at the till. Tap a tile during a sale to drop it
          into the cart.
        </p>
      ) : (
        <div className="product-grid">
          {filtered.map((p) => (
            <button
              key={p.id}
              className="product-tile"
              onClick={() => onPick(p)}
              title={p.description ?? p.name}
            >
              {p.emoji && <span className="product-emoji">{p.emoji}</span>}
              <span className="product-name">{p.name}</span>
              <span className="product-price">
                {p.price_sats.toLocaleString()} sats
              </span>
              <span
                className="product-edit"
                onClick={(e) => {
                  e.stopPropagation();
                  setEditing(p);
                }}
                role="button"
                aria-label={`Edit ${p.name}`}
                title="Edit"
              >
                ✎
              </span>
            </button>
          ))}
        </div>
      )}

      {editing && (
        <ProductEditor
          product={editing === "new" ? null : editing}
          onSave={(p) => {
            if (editing === "new") {
              addProduct(p);
            } else {
              updateProduct(editing.id, p);
            }
            setEditing(null);
          }}
          onDelete={
            editing === "new"
              ? undefined
              : () => {
                  if (
                    window.confirm(
                      `Delete "${editing.name}" from the catalog? Past sales aren't affected.`,
                    )
                  ) {
                    deleteProduct(editing.id);
                    setEditing(null);
                  }
                }
          }
          onCancel={() => setEditing(null)}
        />
      )}
    </div>
  );
}

interface EditorProps {
  /// `null` means "new product"; an existing one means "edit".
  product: Product | null;
  onSave: (p: Omit<Product, "id">) => void;
  onDelete?: () => void;
  onCancel: () => void;
}

function ProductEditor({ product, onSave, onDelete, onCancel }: EditorProps) {
  const [name, setName] = useState(product?.name ?? "");
  const [price, setPrice] = useState(
    product ? String(product.price_sats) : "",
  );
  const [emoji, setEmoji] = useState(product?.emoji ?? "");
  const [description, setDescription] = useState(product?.description ?? "");
  const [category, setCategory] = useState(product?.category ?? "");
  const [err, setErr] = useState<string | null>(null);

  const submit = () => {
    const cleanName = name.trim();
    if (!cleanName) {
      setErr("Name is required.");
      return;
    }
    const sats = Number(price);
    if (!Number.isFinite(sats) || sats <= 0 || !Number.isInteger(sats)) {
      setErr("Price must be a positive whole number of sats.");
      return;
    }
    onSave({
      name: cleanName,
      price_sats: sats,
      emoji: emoji.trim() || undefined,
      description: description.trim() || undefined,
      category: category.trim() || undefined,
    });
  };

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <h2>{product ? `Edit ${product.name}` : "New product"}</h2>
          {product && onDelete && (
            <button className="btn-secondary btn-sm" onClick={onDelete}>
              Delete
            </button>
          )}
        </div>
        {err && (
          <div className="pill fail" style={{ alignSelf: "flex-start" }}>
            {err}
          </div>
        )}
        <div className="row">
          <div className="col" style={{ flex: 1 }}>
            <label>Emoji</label>
            <input
              maxLength={4}
              value={emoji}
              onChange={(e) => setEmoji(e.target.value)}
              placeholder="☕"
              style={{ fontSize: 18 }}
            />
          </div>
          <div className="col" style={{ flex: 3 }}>
            <label>Name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>
        </div>
        <div className="row">
          <div className="col" style={{ flex: 1 }}>
            <label>Price (sats)</label>
            <input
              type="number"
              min={1}
              value={price}
              onChange={(e) => setPrice(e.target.value)}
            />
          </div>
          <div className="col" style={{ flex: 1 }}>
            <label>Category (optional)</label>
            <input
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="Drinks, Food, …"
              list="merchant-category-suggestions"
            />
          </div>
        </div>
        <div className="col">
          <label>Description (optional)</label>
          <textarea
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Espresso, oat milk, single shot"
          />
        </div>
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 4 }}>
          <button
            className="btn-secondary"
            onClick={onCancel}
            style={{ marginRight: 8 }}
          >
            Cancel
          </button>
          <button className="btn-primary" onClick={submit}>
            {product ? "Save" : "Add product"}
          </button>
        </div>
      </div>
    </div>
  );
}
