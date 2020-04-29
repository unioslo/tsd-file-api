
-- postgres backend notes

-- now let's do some basic JSON selections to see what kind of SQL code
-- is generated

-- for selecting specific entries in an array like key2[0] we can rely on array
-- functionality in the json1 extension, e.g.

-- when array elements are maps, instead of single elements like strings, or scalars
-- then one typically wants to perform key selection inside the array elements
-- and then typically, one wants those selections to apply to all elements
-- just like it does on the uppper level

-- postgres does not have rich enough json processing functions
-- to be able to do key selection in arrays

drop function if exists filter_array_elements(jsonb, text[]);
create or replace function filter_array_elements(data jsonb, keys text[])
    returns jsonb as $$
    declare key text;
    declare element jsonb;
    declare filtered jsonb;
    declare out jsonb;
    begin
        for element in select jsonb_array_elements(data) loop
            for key in select unnest(keys) loop
                if filtered is not null then
                    filtered := filtered || jsonb_build_object(key, jsonb_extract_path(element, key));
                else
                    filtered := jsonb_build_object(key, jsonb_extract_path(element, key));
                end if;
            end loop;
            if out is not null then
                out := out || jsonb_build_array(filtered)::jsonb;
            else
                out := jsonb_build_array(filtered)::jsonb;
            end if;
        end loop;
        return out;
    end;
$$ language plpgsql;
